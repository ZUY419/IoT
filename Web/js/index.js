// 記錄目前正在執行的設備名稱與分頁狀態
var started_device = "";
var current_tab = "";
var log_history = "";         // 專門保存 Terminal 歷史 Log (不含 AI 及 Share Memory)
var ai_history = "";          // 專門保存 AI 互動歷史 Log
var share_memory_data = "";  // 🟢 專門保存最新的共享記憶體資料

const HOSTNAME = window.location.hostname || "localhost";
const API_BASE_URL = `http://${HOSTNAME}:8000`;
const WS_BASE_URL = `ws://${HOSTNAME}:8000`;

// 分頁切換
async function switch_button_state(clickedButton) {
    const buttonValue = clickedButton.value;
    current_tab = buttonValue;

    const AllButton = document.querySelectorAll(".switch_show_button");
    AllButton.forEach(btn => {
        if (btn !== clickedButton) {
            btn.classList.remove("action");
            btn.style.fontSize = "";
        } else {
            btn.classList.add("action");
            btn.style.fontSize = "22px";
        }
    });

    const info_show_block = document.querySelector(".info_show_block");
    const info_title_name = document.querySelector(".info_title_name");
    const info_title_data = document.querySelector(".info_title_data");
    const pentest_state = document.querySelector(".pentest_state");

    info_show_block.innerHTML = "";
    info_title_name.textContent = "";
    info_title_data.textContent = "";
    pentest_state.textContent = "";

    if (buttonValue === "Shared Memory") {
        // 🟢 渲染共享記憶體分頁
        info_title_name.textContent = "當前共享記憶體的資料";
        const content = share_memory_data !== "" ? escapeHtml(share_memory_data) : "尚未收獲共享記憶體更新資料...";
        info_show_block.innerHTML = `<div class="memory_show_block" id="memory_container">${content}</div>`;

    } else if (buttonValue === "Tool History") {
        info_title_name.textContent = "當前使用過的工具";
        info_show_block.innerHTML = `<p style="color: #FFF8F0;">工具歷史紀錄...</p>`;

    } else if (buttonValue === "AI Interaction") {
        info_title_name.textContent = "與 AI 的對話紀錄";
        info_show_block.innerHTML = `<div class="ai_show_block" id="ai_container">${ai_history}</div>`;
        scrollToBottom("ai_container");

    } else if (buttonValue === "Terminal") {
        info_title_name.textContent = "當前工具 Terminal Log";
        info_show_block.innerHTML = `<div class="terminal_show_block" id="terminal_container">${log_history}</div>`;
        scrollToBottom("terminal_container");

    } else if (buttonValue === "IoT Devices") {
        info_title_name.textContent = "當前設備:";
        info_title_data.textContent = started_device !== "" ? started_device : "尚未選擇設備";

        const devices_name = await get_devices_name();
        if (devices_name && devices_name.length > 0) {
            let devicesHTML = "";
            devices_name.forEach(file_name => {
                const isStarted = (file_name === started_device);
                const btnText = isStarted ? "Started" : "Start";
                const btnColor = isStarted ? "color: #092328;" : "";

                devicesHTML += `
                    <div class="device_selection_block" id="dev_${file_name}">
                        <p class="device_name">${file_name}</p>
                        <button class="device_button" id="${file_name}" style="${btnColor}" onclick="start_device(this)">${btnText}</button>
                    </div>
                `;
            });
            info_show_block.innerHTML = devicesHTML;
        } else {
            info_show_block.innerHTML = `<p class="device_name" style="color: #f87171;">找不到任何 IoT 設備檔案</p>`;
        }
    }
}

// 啟動設備測試
async function start_device(clickedButton) {
    const deviceName = clickedButton.id;

    if (started_device === "") {
        clickedButton.textContent = "Started";
        clickedButton.style.color = "#092328";

        started_device = deviceName;

        const info_title_data = document.querySelector(".info_title_data");
        if (info_title_data) info_title_data.textContent = deviceName;
        
        initReceiver();
        await start_pentest(deviceName);
    } else if (started_device !== deviceName) {
        alert(`目前已有設備 [${started_device}] 正在執行中，請先停止它！`);
    }
}

let wsB = null;

// 通用自動滾動到底部
function scrollToBottom(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

// 初始化並連線 WebSocket
function initReceiver() {
    if (wsB && wsB.readyState === WebSocket.OPEN) return;

    wsB = new WebSocket(`${WS_BASE_URL}/ws/receive_b`);

    wsB.onopen = function() {
        console.log("[WebSocket] 成功連線至即時日誌接收通道");
    };

    wsB.onmessage = function(event) {
        const data = JSON.parse(event.data);

        // 🔀 條件判斷與訊息分流
        if (data.log_type === "AI_PROMPT" || data.log_type === "AI_RESPONSE") {
            // ================= 1. AI 專用 Log =================
            const isPrompt = data.log_type === "AI_PROMPT";
            const roleClass = isPrompt ? "ai_msg_prompt" : "ai_msg_response";
            const roleLabel = isPrompt ? "PROMPT / Prompt" : "AI RESPONSE";

            const newAiHTML = `
                <div class="ai_message_card ${roleClass}">
                    <div class="ai_msg_header">${roleLabel}</div>
                    <div class="ai_msg_body">${escapeHtml(data.log)}</div>
                </div>
            `;
            ai_history += newAiHTML;

            if (current_tab === "AI Interaction") {
                const aiContainer = document.getElementById("ai_container");
                if (aiContainer) {
                    aiContainer.insertAdjacentHTML('beforeend', newAiHTML);
                    scrollToBottom("ai_container");
                }
            }

        } else if (data.log_type === "SHARE_MEMORY") {
            // ================= 2. 🟢 共享記憶體更新 (排除於 Terminal) =================
            share_memory_data = data.log;

            if (current_tab === "Shared Memory") {
                const memContainer = document.getElementById("memory_container");
                if (memContainer) {
                    memContainer.innerHTML = escapeHtml(share_memory_data);
                }
            }

        } else {
            // ================= 3. Terminal 工具 Log (排除 AI 與 SHARE_MEMORY) =================
            const newTerminalLogHTML = `
                <div class="log_${data.log_type}_section">
                    <span class="log_type_${data.log_type}">${data.log_type}</span> 
                    <span class="log_content_${data.log_type}">${escapeHtml(data.log)}</span>
                </div>
            `;
            log_history += newTerminalLogHTML;

            if (current_tab === "Terminal") {
                const termContainer = document.getElementById("terminal_container");
                if (termContainer) {
                    termContainer.insertAdjacentHTML('beforeend', newTerminalLogHTML);
                    scrollToBottom("terminal_container");
                }
            }
        }
    };

    wsB.onclose = function() {
        console.warn("[WebSocket] 連線已斷開，3 秒後嘗試自動重連...");
        setTimeout(() => {
            if (started_device !== "") initReceiver();
        }, 3000);
    };

    wsB.onerror = function(err) {
        console.error("[WebSocket Exception]", err);
    };
}

// 安全字元轉換 (避免 XSS 注入)
function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// 取得裝置清單 API
async function get_devices_name() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/pentest/get_devices_list`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            return data.files_name;
        } else {
            return [];
        }
    } catch (error) {
        return [];
    }
}

// 發送 start_pentest API
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

// 頁面初始化
window.addEventListener("DOMContentLoaded", () => {
    pentest_button_init();
});

function pentest_button_init() {
    const firstButton = document.querySelector(".switch_show_button");
    if (firstButton) {
        switch_button_state(firstButton);
    }
}