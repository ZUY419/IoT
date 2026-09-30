"use strict";

// ===== 全域狀態管理 =====
const state = {
    started_device: "",
    current_tab: "",
    current_tool: "",
    log_history: "",
    ai_history: "",
    share_memory_data: null,
    tool_history_logs: []
};

// 效能設定
const CONFIG = {
    MAX_LOG_ENTRIES: 300,        // Terminal / AI 訊息最大保留數
    RECONNECT_INTERVAL: 3000,   // WebSocket 重連間隔 (ms)
    BOTTOM_THRESHOLD: 60         // 判定為「處於最底部」的容許像素範圍 (px)
};

let wsB = null;
let reconnectTimer = null;

// 動態伺服器位址設定 (自動匹配 Host，避免硬編碼 localhost)
const HOSTNAME = window.location.hostname || "localhost";
const API_BASE_URL = `http://${HOSTNAME}:8000`;
const WS_BASE_URL = `ws://${HOSTNAME}:8000`;

// ===== 智慧滾動輔助函式 =====

/**
 * 檢查指定的捲動容器目前是否處於（或接近）最底部
 * @param {HTMLElement} container 
 * @param {number} threshold 判定閾值（預設 60px）
 * @returns {boolean}
 */
function isScrolledNearBottom(container, threshold = CONFIG.BOTTOM_THRESHOLD) {
    if (!container) return false;
    const distanceToBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    return distanceToBottom <= threshold;
}

/**
 * 將指定容器順暢滾動至最底部
 * @param {string} containerId 
 */
function scrollToBottom(containerId) {
    requestAnimationFrame(() => {
        const container = document.getElementById(containerId);
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    });
}

/**
 * 修剪過多的舊 DOM 節點以增進效能
 */
function pruneContainerChildren(container, maxCount) {
    while (container.children.length > maxCount) {
        container.removeChild(container.firstChild);
    }
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ===== 1. 分頁切換與 UI 渲染 =====
async function switch_button_state(clickedButton) {
    if (!clickedButton) return;

    const buttonValue = clickedButton.value;
    state.current_tab = buttonValue;

    // 按鈕高亮切換
    const allButtons = document.querySelectorAll(".switch_show_button");
    allButtons.forEach(btn => {
        const isSelected = (btn === clickedButton);
        btn.classList.toggle("action", isSelected);
        btn.style.fontSize = isSelected ? "22px" : "";
    });

    const info_show_block = document.querySelector(".info_show_block");
    const info_title_name = document.querySelector(".info_title_name");
    const info_title_data = document.querySelector(".info_title_data");
    const pentest_state = document.querySelector(".pentest_state");

    if (!info_show_block) return;

    // 清空顯示區塊與標題
    info_show_block.innerHTML = "";
    if (info_title_name) info_title_name.textContent = "";
    if (info_title_data) info_title_data.textContent = "";
    if (pentest_state) pentest_state.textContent = "";

    // 分頁渲染邏輯 (切換分頁時預設拉到底部)
    switch (buttonValue) {
        case "Shared Memory":
            if (info_title_name) info_title_name.textContent = "當前共享記憶體的資料";
            render_share_memory();
            break;

        case "Tool History":
            if (info_title_name) info_title_name.textContent = "當前使用過的工具";
            render_tool_history();
            break;

        case "AI Interaction":
            if (info_title_name) info_title_name.textContent = "與 AI 的對話紀錄";
            info_show_block.innerHTML = `<div class="ai_show_block" id="ai_container">${state.ai_history}</div>`;
            scrollToBottom("ai_container");
            break;

        case "Terminal":
            if (info_title_name) info_title_name.textContent = "當前工具";
            if (info_title_data) {
                info_title_data.textContent = state.current_tool !== "" 
                    ? state.current_tool 
                    : "尚未開啟設備或是尚未使用到任何工具";
            }
            info_show_block.innerHTML = `<div class="terminal_show_block" id="terminal_container">${state.log_history}</div>`;
            scrollToBottom("terminal_container");
            break;

        case "IoT Devices":
            if (info_title_name) info_title_name.textContent = "當前設備:";
            if (info_title_data) {
                info_title_data.textContent = state.started_device !== "" ? state.started_device : "尚未選擇設備";
            }
            await render_iot_devices(info_show_block);
            break;

        default:
            console.warn(`[UI] 未知的分頁標籤: ${buttonValue}`);
            break;
    }
}

// 渲染 IoT 設備選單
async function render_iot_devices(container) {
    const devices_name = await get_devices_name();
    if (devices_name && devices_name.length > 0) {
        const devicesHTML = devices_name.map(file_name => {
            const isStarted = (file_name === state.started_device);
            return `
                <div class="device_selection_block" id="dev_${escapeHtml(file_name)}">
                    <p class="device_name">${escapeHtml(file_name)}</p>
                    <div class="device_btn_group">
                        <button class="device_button start_btn ${isStarted ? 'active' : ''}" 
                                id="start_${escapeHtml(file_name)}" 
                                onclick="start_device('${escapeHtml(file_name)}')" 
                                ${isStarted ? 'disabled' : ''}>
                            ${isStarted ? 'Running' : 'Start'}
                        </button>
                        <button class="device_button stop_btn" 
                                id="stop_${escapeHtml(file_name)}" 
                                onclick="stop_device('${escapeHtml(file_name)}')" 
                                ${!isStarted ? 'disabled' : ''}>
                            Stop
                        </button>
                    </div>
                </div>
            `;
        }).join("");
        container.innerHTML = devicesHTML;
    } else {
        container.innerHTML = `<p class="device_name" style="color: #f87171; padding: 10px;">找不到任何 IoT 設備檔案</p>`;
    }
}

// ===== 2. 滲透測試設備控制 (Start / Stop) =====
async function start_device(deviceName) {
    if (state.started_device === "") {
        state.started_device = deviceName;

        const info_title_data = document.querySelector(".info_title_data");
        if (info_title_data) info_title_data.textContent = deviceName;

        await start_pentest(deviceName);

        const currentBtn = document.querySelector(`.switch_show_button[value='IoT Devices']`);
        if (currentBtn) switch_button_state(currentBtn);
    } else if (state.started_device !== deviceName) {
        alert(`目前已有設備 [${state.started_device}] 正在執行中，請先停止它！`);
    }
}

async function stop_device(deviceName) {
    if (state.started_device === deviceName) {
        if (confirm(`確定要停止設備 [${deviceName}] 的滲透測試嗎？`)) {
            await stop_pentest();
            state.started_device = "";

            const info_title_data = document.querySelector(".info_title_data");
            if (info_title_data) info_title_data.textContent = "尚未選擇設備";

            const currentBtn = document.querySelector(`.switch_show_button[value='IoT Devices']`);
            if (currentBtn) switch_button_state(currentBtn);
        }
    }
}

// ===== 3. WebSocket 即時通訊接收器（含 Smart Auto-Scroll） =====
function initReceiver() {
    if (wsB && (wsB.readyState === WebSocket.OPEN || wsB.readyState === WebSocket.CONNECTING)) return;

    if (reconnectTimer) clearTimeout(reconnectTimer);

    wsB = new WebSocket(`${WS_BASE_URL}/ws/receive_b`);

    wsB.onopen = function() {
        console.log("[WebSocket] 成功連線至即時日誌接收通道");
    };

    wsB.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            const log_type = (data.log_type || "").toUpperCase();

            // 分流 1：AI 對話訊息
            if (log_type === "AI_PROMPT" || log_type === "AI_RESPONSE") {
                const isPrompt = log_type === "AI_PROMPT";
                const roleClass = isPrompt ? "ai_msg_prompt" : "ai_msg_response";
                const roleLabel = isPrompt ? "PROMPT / User" : "AI RESPONSE";

                const newAiHTML = `
                    <div class="ai_message_card ${roleClass}">
                        <div class="ai_msg_header">${roleLabel}</div>
                        <div class="ai_msg_body">${escapeHtml(data.log)}</div>
                    </div>
                `;
                state.ai_history += newAiHTML;

                if (state.current_tab === "AI Interaction") {
                    const aiContainer = document.getElementById("ai_container");
                    if (aiContainer) {
                        // 插入新數據前判斷是否在底部
                        const isAtBottom = isScrolledNearBottom(aiContainer);

                        aiContainer.insertAdjacentHTML('beforeend', newAiHTML);
                        pruneContainerChildren(aiContainer, CONFIG.MAX_LOG_ENTRIES);

                        // 只有當原本就在底部時才自動滾動
                        if (isAtBottom) {
                            scrollToBottom("ai_container");
                        }
                    }
                }

            // 分流 2：共享記憶體更新
            } else if (log_type === "SHARE_MEMORY") {
                state.share_memory_data = data.log;

                if (state.current_tab === "Shared Memory") {
                    render_share_memory();
                }

            // 分流 3：一般 Terminal Log (INFO, TOOL, WARN, ERROR 等)
            } else {
                if (log_type === "TOOL") {
                    state.current_tool = data.log;
                    state.tool_history_logs.push(data);
                    
                    if (state.current_tab === "Tool History") {
                        render_tool_history();
                    }
                }

                const newTerminalLogHTML = `
                    <div class="log_${log_type}_section">
                        <span class="log_type_${log_type}">${log_type}</span> 
                        <span class="log_content_${log_type}">${escapeHtml(data.log)}</span>
                    </div>
                `;
                state.log_history += newTerminalLogHTML;

                if (state.current_tab === "Terminal") {
                    const termContainer = document.getElementById("terminal_container");
                    if (termContainer) {
                        // 插入新 Log 前先檢測使用者位置
                        const isAtBottom = isScrolledNearBottom(termContainer);

                        termContainer.insertAdjacentHTML('beforeend', newTerminalLogHTML);
                        pruneContainerChildren(termContainer, CONFIG.MAX_LOG_ENTRIES);

                        // 若原本就在最底下，才跟著自動滑動
                        if (isAtBottom) {
                            scrollToBottom("terminal_container");
                        }
                    }
                }
            }
        } catch (e) {
            console.error("解析 WebSocket 廣播資料失敗:", e);
        }
    };

    wsB.onclose = function() {
        console.warn(`[WebSocket] 連線中斷，${CONFIG.RECONNECT_INTERVAL / 1000} 秒後自動重連...`);
        reconnectTimer = setTimeout(() => {
            initReceiver();
        }, CONFIG.RECONNECT_INTERVAL);
    };

    wsB.onerror = function(err) {
        console.error("[WebSocket 錯誤]", err);
    };
}

// ===== 4. 工具歷史紀錄 (Tool History) 渲染器 =====
function render_tool_history() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;

    if (state.tool_history_logs.length === 0) {
        info_show_block.innerHTML = `<p style="color: #FFF8F0; opacity: 0.7; padding: 20px; text-align: center;">尚未收到工具執行紀錄...</p>`;
        return;
    }

    let html = `<div style="display: flex; flex-direction: column; gap: 10px; height: 100%; overflow-y: auto;">`;
    state.tool_history_logs.forEach((item, index) => {
        html += `
            <div class="tool_card">
                <div class="tool_card_header">
                    <div class="tool_title_group">
                        <span class="tool_badge">Tool #${index + 1}</span>
                        <span class="tool_name">${escapeHtml(item.log_type)}</span>
                    </div>
                </div>
                <div class="tool_card_body">
                    <div class="tool_argument">${escapeHtml(item.log)}</div>
                </div>
            </div>
        `;
    });
    html += `</div>`;

    info_show_block.innerHTML = html;
}

// ===== 5. 通用型共享記憶體 (Shared Memory) 動態渲染器 =====
function render_share_memory() {
    const info_show_block = document.querySelector(".info_show_block");
    if (!info_show_block) return;

    const rawData = state.share_memory_data;
    if (!rawData || (typeof rawData === "string" && rawData.trim() === "")) {
        info_show_block.innerHTML = `<div class="memory_empty_notice">尚未收到共享記憶體更新資料...</div>`;
        return;
    }

    let parsedData;
    try {
        parsedData = (typeof rawData === "string") ? JSON.parse(rawData) : rawData;
    } catch (e) {
        info_show_block.innerHTML = `<div class="memory_show_block">${escapeHtml(String(rawData))}</div>`;
        return;
    }

    let html = `<div class="memory_dashboard">`;
    html += renderGenericJson(parsedData, 0);

    html += `
        <details class="raw_json_details">
            <summary>📄 檢視原始 JSON 資料 (Raw JSON)</summary>
            <div class="memory_show_block">${escapeHtml(JSON.stringify(parsedData, null, 2))}</div>
        </details>
    `;
    html += `</div>`;

    info_show_block.innerHTML = html;
}

// 遞迴解析任意 JSON 物件/陣列結構
function renderGenericJson(data, level = 0) {
    if (data === null || data === undefined) {
        return `<span class="val_null">null</span>`;
    }

    if (typeof data !== "object") {
        return `<span class="val_primitive">${escapeHtml(String(data))}</span>`;
    }

    // 陣列處理
    if (Array.isArray(data)) {
        if (data.length === 0) return `<div class="val_empty">[ 空清單 ]</div>`;

        const isArrayOfObjects = data.every(item => typeof item === "object" && item !== null && !Array.isArray(item));

        if (isArrayOfObjects) {
            const allKeys = Array.from(new Set(data.flatMap(item => Object.keys(item))));

            let tableHtml = `<div class="table_responsive"><table class="mem_table"><thead><tr>`;
            allKeys.forEach(k => {
                tableHtml += `<th>${escapeHtml(formatKeyName(k))}</th>`;
            });
            tableHtml += `</tr></thead><tbody>`;

            data.forEach(item => {
                tableHtml += `<tr>`;
                allKeys.forEach(k => {
                    const val = item[k];
                    tableHtml += `<td>${val !== undefined ? renderGenericJson(val, level + 1) : '<span class="val_null">-</span>'}</td>`;
                });
                tableHtml += `</tr>`;
            });

            tableHtml += `</tbody></table></div>`;
            return tableHtml;
        } else {
            let listHtml = `<div class="generic_array_group">`;
            data.forEach(item => {
                listHtml += `<div class="array_tag_item">${renderGenericJson(item, level + 1)}</div>`;
            });
            listHtml += `</div>`;
            return listHtml;
        }
    }

    // 物件處理
    const entries = Object.entries(data);
    if (entries.length === 0) return `<div class="val_empty">{ 空物件 }</div>`;

    const primitives = entries.filter(([_, v]) => typeof v !== "object" || v === null);
    const complex = entries.filter(([_, v]) => typeof v === "object" && v !== null);

    let objHtml = "";

    if (primitives.length > 0) {
        const gridContent = primitives.map(([k, v]) => `
            <div class="mem_info_item">
                <span class="mem_label">${escapeHtml(formatKeyName(k))}:</span>
                <span class="mem_val">${escapeHtml(String(v))}</span>
            </div>
        `).join("");

        if (level === 0) {
            objHtml += `
                <div class="mem_card">
                    <div class="mem_card_title">📌 基本屬性 (Properties)</div>
                    <div class="mem_info_grid">${gridContent}</div>
                </div>
            `;
        } else {
            objHtml += `<div class="mem_info_grid" style="margin-bottom: 10px;">${gridContent}</div>`;
        }
    }

    complex.forEach(([k, v]) => {
        const title = formatKeyName(k);
        objHtml += `
            <div class="mem_card">
                <div class="mem_card_title">📂 ${escapeHtml(title)}</div>
                <div class="mem_card_body">
                    ${renderGenericJson(v, level + 1)}
                </div>
            </div>
        `;
    });

    return objHtml;
}

// 格式化 Key 名稱 (例：device_information -> Device Information)
function formatKeyName(key) {
    return String(key)
        .replace(/([a-z])([A-Z])/g, '\$1 \$2')
        .replace(/[_-]+/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

// ===== 6. 輔助 API 呼叫 =====
async function get_devices_name() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/get_devices_list`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            return data.files_name || [];
        } else {
            return [];
        }
    } catch (error) {
        console.error("取得裝置清單失敗:", error);
        return [];
    }
}

async function start_pentest(deviceName) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/start_pentest`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_name: deviceName })
        });

        if (response.ok) {
            console.log(`[Pentest] 成功啟動裝置 [${deviceName}]！`);
        } else {
            const errData = await response.json();
            alert(`啟動失敗: ${errData.message || response.statusText}`);
        }
    } catch (error) {
        console.error("無法啟動測試:", error);
    }
}

async function stop_pentest() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/stop_pentest`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            console.log(`[Pentest] ${data.message}`);
        } else {
            console.error("發送停止請求失敗");
        }
    } catch (error) {
        console.error("無法發送停止滲透測試請求:", error);
    }
}

function pentest_button_init() {
    const firstButton = document.querySelector(".switch_show_button");
    if (firstButton) {
        switch_button_state(firstButton);
    }
}

// 頁面初始化與卸載事件
window.addEventListener("DOMContentLoaded", () => {
    initReceiver();
    pentest_button_init();
});

window.addEventListener("beforeunload", () => {
    if (wsB) {
        wsB.onclose = null; // 避免離開頁面時觸發重連機制
        wsB.close();
    }
});
