import time
import requests
from lxml import html

# Paths to configuration files
FILE_HIGH_TRAFFIC = "/home/mininet/faucet_ruch_przekroczony.yaml"
FILE_LOW_TRAFFIC = "/home/mininet/faucet_brak_ruchu.yaml"
CURRENT_CONFIG = "/etc/faucet/faucet.yaml"

# Monitoring settings
PROMETHEUS_URL = "http://localhost:9090"
PROMETHEUS_TARGETS_URL = "http://localhost:9090/targets"
DP_ID = "0x1"
PORT = "2"
THRESHOLD_MB = 10  # Traffic threshold in MB
SCRAPE_INTERVAL = 5  # Fixed scrape interval in Prometheus configuration
SCRAPE_COUNT_RESET = 8  # Number of scrapes before switching back to the main configuration
XPATH = '/html/body/div/div[2]/table/tbody/tr/td[4]'

def get_last_scrape_with_xpath(url, xpath):
    """Fetch the last scrape time from the Prometheus interface using XPath."""
    response = requests.get(url)
    response.raise_for_status()
    html_content = response.text
    tree = html.fromstring(html_content)
    last_scrape = tree.xpath(xpath)
    if last_scrape:
        last_scrape_text = last_scrape[0].text_content().strip()
        print(f"Last Scrape: {last_scrape_text}")
        return last_scrape_text
    else:
        print("Could not find data with the given XPath.")
        return None

def parse_scrape_interval(scrape_text):
    """Convert 'ms ago' or 's ago' to seconds."""
    if 'ms' in scrape_text:
        return float(scrape_text.split('ms')[0]) / 1000  # Milliseconds to seconds
    elif 's' in scrape_text:
        return float(scrape_text.split('s')[0])  # Seconds
    else:
        print("Unexpected format for scrape time.")
        return 0

def get_tx_bytes(prometheus_url, dp_id, port):
    """Fetch the number of transmitted bytes on a port."""
    query = f'of_port_tx_bytes{{dp_id="{dp_id}",port="{port}"}}'
    response = requests.get(f"{prometheus_url}/api/v1/query", params={"query": query})
    response.raise_for_status()
    result = response.json().get("data", {}).get("result", [])
    if result:
        return int(result[0]["value"][1])  # First result (value in bytes)
    return 0

def overwrite_config(source_file, target_file):
    """Overwrite the target file's content with the content of the source file."""
    try:
        with open(source_file, "r") as src, open(target_file, "w") as tgt:
            tgt.write(src.read())
        print(f"Config overwritten with contents of: {source_file}")
    except Exception as e:
        print(f"Error overwriting config: {e}")

def monitor_traffic():
    prev_tx_bytes = get_tx_bytes(PROMETHEUS_URL, DP_ID, PORT)
    scrape_count_below_threshold = 0  # Counter for consecutive low-traffic scrapes
    high_traffic_mode = False  # Current traffic mode

    while True:
        # Fetch the last scrape time
        last_scrape_text = get_last_scrape_with_xpath(PROMETHEUS_TARGETS_URL, XPATH)
        if last_scrape_text is None:
            print("Failed to fetch last scrape time. Retrying in 5 seconds...")
            time.sleep(5)
            continue

        # Calculate time until the next scrape
        time_since_last_scrape = parse_scrape_interval(last_scrape_text)
        time_until_next_scrape = SCRAPE_INTERVAL - time_since_last_scrape
        if time_until_next_scrape < 0:
            time_until_next_scrape = 0
        print(f"Sleeping for {time_until_next_scrape:.2f} seconds to synchronize with the next scrape.")
        time.sleep(time_until_next_scrape)

        # Monitor traffic
        curr_tx_bytes = get_tx_bytes(PROMETHEUS_URL, DP_ID, PORT)
        delta_bytes = curr_tx_bytes - prev_tx_bytes
        if delta_bytes < 0:  # Handle counter reset
            delta_bytes = curr_tx_bytes
        prev_tx_bytes = curr_tx_bytes

        # Calculate traffic in MB
        traffic_mb = (delta_bytes * 8) / (1_000_000 * SCRAPE_INTERVAL)  # Convert bytes to MB
        print(f"Traffic: {traffic_mb:.2f} MB")

        if traffic_mb > THRESHOLD_MB:
            # If traffic exceeds the threshold, switch to high traffic mode immediately
            if not high_traffic_mode:
                overwrite_config(FILE_HIGH_TRAFFIC, CURRENT_CONFIG)
                high_traffic_mode = True
                scrape_count_below_threshold = 0  # Reset low traffic counter
            else:
                # Reset scrape_count_below_threshold if already in high traffic mode
                scrape_count_below_threshold = 0
            print(f"High traffic detected. Reset scrape_count_below_threshold to {scrape_count_below_threshold}.")
        else:
            # If traffic is below the threshold, increment the low traffic counter
            scrape_count_below_threshold += 1
            print(f"Low traffic detected. scrape_count_below_threshold: {scrape_count_below_threshold}")
            
            if high_traffic_mode and scrape_count_below_threshold >= SCRAPE_COUNT_RESET:
                # Switch back to low traffic mode after consecutive low scrapes
                overwrite_config(FILE_LOW_TRAFFIC, CURRENT_CONFIG)
                high_traffic_mode = False
                scrape_count_below_threshold = 0  # Reset counter after mode switch
                print(f"Switched to low traffic mode. Reset scrape_count_below_threshold to {scrape_count_below_threshold}.")


if __name__ == "__main__":
    monitor_traffic()
