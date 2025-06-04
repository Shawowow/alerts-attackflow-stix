import requests
import json

# List of Wazuh alert payloads
wazuh_alerts = [
    # T1566.002 - Spearphishing Link
    {
        "timestamp": "2023-05-15T14:37:22.123Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91546",
            "level": 10,
            "description": "Windows process creation detected",
            "mitre": {
                "id": ["T1566.002"],
                "tactic": ["Initial Access"],
                "technique": ["Spearphishing Link"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 14:37:21.456",
                    "processId": "5432",
                    "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe",
                    "parentProcessId": "4321",
                    "commandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --new-window https://suspicious-link.example.com",
                    "user": "DOMAIN\\username"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123456",
                    "processID": "0x4",
                    "threadID": "0x5",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # T1078.001 - Valid Accounts
    {
        "timestamp": "2023-05-15T15:22:45.789Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91547",
            "level": 10,
            "description": "Windows process creation detected - User account management",
            "mitre": {
                "id": ["T1078.001"],
                "tactic": ["Initial Access"],
                "technique": ["Valid Accounts"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 15:22:45.123",
                    "processId": "2345",
                    "image": "C:\\Windows\\System32\\net.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "1234",
                    "commandLine": "net user guest /active:yes",
                    "user": "SYSTEM"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123457",
                    "processID": "0x6",
                    "threadID": "0x7",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "WARNING",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # T1135 - Network Share Discovery
    {
        "timestamp": "2023-05-15T15:45:30.456Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91548",
            "level": 8,
            "description": "Windows process creation detected - Network share enumeration",
            "mitre": {
                "id": ["T1135"],
                "tactic": ["Discovery"],
                "technique": ["Network Share Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 15:45:30.123",
                    "processId": "3456",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "2345",
                    "commandLine": "powershell.exe -Command \"Get-SmbShare -ComputerName Server01\"",
                    "user": "DOMAIN\\username"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123458",
                    "processID": "0x8",
                    "threadID": "0x9",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # T1046 - Network Service Discovery
    {
        "timestamp": "2023-05-15T16:15:30.456Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91549",
            "level": 8,
            "description": "Windows process creation detected - Network service discovery",
            "mitre": {
                "id": ["T1046"],
                "tactic": ["Discovery"],
                "technique": ["Network Service Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 16:15:30.123",
                    "processId": "3456",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "2345",
                    "commandLine": "powershell.exe -Command \"Get-Service -Name \\\"Remote Desktop Services\\\"\"",
                    "user": "DOMAIN\\username"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123458",
                    "processID": "0x8",
                    "threadID": "0x9",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # T1083 - File and Directory Discovery
    {
        "timestamp": "2023-05-15T16:30:30.456Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91550",
            "level": 8,
            "description": "Windows process creation detected - File and directory discovery",
            "mitre": {
                "id": ["T1083"],
                "tactic": ["Discovery"],
                "technique": ["File and Directory Discovery"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 16:30:30.123",
                    "processId": "3456",
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "2345",
                    "commandLine": "powershell.exe -Command \"Get-ChildItem -Recurse C:\\Users\"",
                    "user": "DOMAIN\\username"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123458",
                    "processID": "0x8",
                    "threadID": "0x9",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "INFO",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # T1552.001 - Credentials in Files
    {
        "timestamp": "2023-05-15T16:45:30.456Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91551",
            "level": 10,
            "description": "Windows process creation detected - Credential hunting",
            "mitre": {
                "id": ["T1552.001"],
                "tactic": ["Credential Access"],
                "technique": ["Credentials In Files"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 16:45:30.123",
                    "processId": "3456",
                    "image": "C:\\Windows\\System32\\cmd.exe",
                    "parentImage": "C:\\Windows\\System32\\explorer.exe",
                    "parentProcessId": "2345",
                    "commandLine": "cmd.exe /c findstr /si password C:\\Users\\*.txt",
                    "user": "DOMAIN\\username"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123458",
                    "processID": "0x8",
                    "threadID": "0x9",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "WARNING",
                    "message": "A new process has been created."
                }
            }
        }
    },
    
    # T1078.003 - Local Account Creation
    {
        "timestamp": "2023-05-15T16:45:30.456Z",
        "agent": {
            "id": "001",
            "name": "windows-workstation-01",
            "ip": "192.168.1.100"
        },
        "rule": {
            "id": "91550",
            "level": 10,
            "description": "Windows process creation detected - Local account creation",
            "mitre": {
                "id": ["T1078"],
                "tactic": ["Initial Access", "Persistence", "Privilege Escalation"],
                "technique": ["Valid Accounts: Local Accounts"]
            }
        },
        "data": {
            "win": {
                "eventdata": {
                    "utcTime": "2023-05-15 16:45:30.123",
                    "processId": "4567",
                    "image": "C:\\Windows\\System32\\net.exe",
                    "parentImage": "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessId": "3456",
                    "commandLine": "net user art-test Password123! /add",
                    "user": "SYSTEM"
                },
                "system": {
                    "eventID": "4688",
                    "eventRecordID": "123459",
                    "processID": "0x8",
                    "threadID": "0x9",
                    "channel": "Security",
                    "computer": "windows-workstation-01",
                    "severityValue": "WARNING",
                    "message": "A new process has been created."
                }
            }
        }
    }
]

def send_wazuh_alerts(base_url='http://localhost:8000/wazuh-alerts'):
    """
    Send Wazuh alerts to the specified endpoint
    
    :param base_url: Base URL for sending Wazuh alerts (default: localhost)
    :return: List of response statuses
    """
    responses = []
    
    for index, alert in enumerate(wazuh_alerts, 1):
        try:
            # Send POST request
            response = requests.post(
                base_url, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(alert)
            )
            
            # Print status for each alert
            print(f"Alert {index} (MITRE ID: {alert['rule']['mitre']['id'][0]}):")
            print(f"  Description: {alert['rule']['description']}")
            print(f"  Status Code: {response.status_code}")
            
            # Store response for potential further processing
            responses.append({
                'mitre_id': alert['rule']['mitre']['id'][0],
                'status_code': response.status_code,
                'description': alert['rule']['description']
            })
            
        except requests.RequestException as e:
            print(f"Error sending alert {index}: {e}")
    
    return responses

def main():
    """
    Main function to demonstrate sending Wazuh alerts
    """
    print("Sending Wazuh Alerts...")
    results = send_wazuh_alerts()
    
    # Optional: More detailed reporting
    print("\nAlert Sending Summary:")
    for result in results:
        print(f"- {result['mitre_id']}: {result['description']} (Status: {result['status_code']})")

if __name__ == '__main__':
    main()