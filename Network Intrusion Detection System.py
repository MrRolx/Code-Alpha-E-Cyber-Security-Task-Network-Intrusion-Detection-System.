ALERT_LOG_PATH = "/var/log/suricata/eve.json"  # Update with the path to your alert file

def parse_alerts(log_path):
    """Parse alerts from Suricata/Snort log file."""
    alerts = []
    try:
        with open(log_path, 'r') as file:
            for line in file:
                alert_data = json.loads(line)
                if "alert" in alert_data:
                    alerts.append({
                        "timestamp": alert_data.get("timestamp", "N/A"),
                        "source_ip": alert_data.get("src_ip", "Unknown"),
                        "destination_ip": alert_data.get("dest_ip", "Unknown"),
                        "protocol": alert_data.get("proto", "Unknown"),
                        "alert_msg": alert_data["alert"].get("signature", "No Signature"),
                    })
    except FileNotFoundError:
        print(f"Log file {log_path} not found.")
    except json.JSONDecodeError:
        print(f"Error decoding JSON in {log_path}.")
    return alerts

def visualize_alerts(alerts):
    """Visualize alerts using a bar chart."""
    if not alerts:
        print("No alerts to visualize.")
        return

    df = pd.DataFrame(alerts)
    alert_counts = df['alert_msg'].value_counts()

    # Plot
    plt.figure(figsize=(10, 6))
    alert_counts.plot(kind='bar', color='skyblue')
    plt.title("Frequency of Alerts")
    plt.xlabel("Alert Message")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

def main():
    """Main function to parse and visualize alerts."""
    print("Parsing alerts...")
    alerts = parse_alerts(ALERT_LOG_PATH)
    
    if alerts:
        print(f"Parsed {len(alerts)} alerts.")
        for alert in alerts[:5]:  # Display the first 5 alerts
            print(alert)
    else:
        print("No alerts found.")
    
    print("Visualizing alerts...")
    visualize_alerts(alerts)
