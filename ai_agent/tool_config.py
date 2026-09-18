TOOL_DESCRIPTION = [
    # {
    #     "type": "function",
    #     "function": {
    #         "name": "nmap_scan_tcp",
    #         "description": "[Stage 1] Performs a TCP port scan and service version detection on the target device. Use this first to discover active ports and services.",
    #         "parameters": {
    #             "type": "object",
    #             "properties": {
    #                 "target_ip": {
    #                     "type": "string",
    #                     "description": "The IP address of the target device."
    #                 }
    #             },
    #             "required": ["target_ip"]
    #         }
    #     }
    # },
    # {
    #     "type": "function",
    #     "function": {
    #         "name": "nmap_scan_udp",
    #         "description": "[Stage 1] Scans common or specified UDP ports on the target device to discover hidden UDP services (e.g., DNS, SNMP).",
    #         "parameters": {
    #             "type": "object",
    #             "properties": {
    #                 "target_ip": {
    #                     "type": "string",
    #                     "description": "The IP address of the target device."
    #                 },
    #                 "ports": {
    #                     "type": "string",
    #                     "description": "The UDP ports to scan, formatted as a string (e.g., '53,69,161')."
    #                 }
    #             },
    #             "required": ["target_ip"]
    #         }
    #     }
    # },
    {
        "type": "function",
        "function": {
            "name": "run_nvd_lookup",
            "description": "[Stage 2] Queries NVD using the specific service, version, protocol, and port to map CVEs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "description": "The protocol of the service, either 'tcp' or 'udp'."
                    },
                    "port": {
                        "type": "string",
                        "description": "The port number of the service (e.g., '53', '80')."
                    },
                    "service_name": {
                        "type": "string",
                        "description": "The exact name of the software or service."
                    },
                    "version": {
                        "type": "string",
                        "description": "The version number of the service."
                    }
                },
                "required": ["protocol", "port", "service_name", "version"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_rag_poc",
            "description": "[Stage 2/3] Searches the local RAG knowledge base for specific device exploits, PoC scripts, or attack guidelines based on a keyword.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query_keyword": {
                        "type": "string",
                        "description": "Search keyword, usually a device brand, model, or CVE ID (e.g., 'D-Link DIR-816' or 'CVE-2017-14491')."
                    }
                },
                "required": ["query_keyword"]
            }
        }
    }
]