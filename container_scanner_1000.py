import os
import subprocess
import platform
import time
import json

# Define the list of images to scan
images_to_scan = [
    # "quay.io/jeslynlamxy/explorer-app:latest",
    # "quay.io/jeslynlamxy/starchat-app:latest",
    # "quay.io/jeslynlamxy/ollama-llama-8b:latest",
    # "quay.io/jeslynlamxy/my-temp-image:latest",
    # "registry.access.redhat.com/ubi9/python-39@sha256:feda42148febbbadaf2ad594a342462b7d0260428e38503c0720610193fb24b6",
    # "registry.access.redhat.com/ubi9/python-311@sha256:3dc479c15b8c8e1e09ca03a6eed59bc2d0f9d2e9291184468460f763999f5bf9",
    # "ollama/ollama:latest",
    # "ollama/ollama:0.3.11",
    "quay.io/jeslynlamxy/ollama-patching:latest"
]

# Set the results directory
results_dir = os.path.join(os.getcwd(), "results")

# Create the results directory if it doesn't exist
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# Define the directory for filtered results
filtered_results_directory = os.path.join(results_dir, "filtered_results")

# Create the filtered results directory if it doesn't exist
if not os.path.exists(filtered_results_directory):
    os.makedirs(filtered_results_directory)

# Get OS platform to adjust commands if needed (Linux/Windows)
is_windows = platform.system() == "Windows"

# Define the base docker command
base_command = [
    "docker",
    "run",
    "-it",
    "-v",
    f"{results_dir}:/results",  # Bind results directory to container
    "aquasec/trivy",
    "image",  # Run the Trivy image scanner
    "-f",
    "json",  # Output format
    "--scanners",
    "vuln",  # Scan for vulnerabilities
    "--timeout",
    "999m",  # Set timeout
]

# Define retry settings
max_retries = None  # Set to None for infinite retries
retry_delay = 5  # Seconds to wait between retries

# Define the severity levels to filter
desired_severities = ["HIGH", "CRITICAL"]


# Function to filter vulnerabilities based on severity
def filter_vulnerabilities(input_file, output_file):
    print(f"Processing file: {input_file}")

    # Load and parse the JSON data from the current file
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            data = json.load(file)
    except UnicodeDecodeError as e:
        print(f"Error reading {input_file}: {e}")
        return  # Skip this file

    # Check if data is a list or dict (e.g., a list of results or results inside a dict)
    if isinstance(data, list):
        results = data
    elif isinstance(data, dict):
        results = data.get("Results", [])
    else:
        print(f"Unexpected data format in {input_file}")
        return  # Skip this file

    # Initialize a list to store the filtered vulnerabilities
    filtered_vulnerabilities = []

    # Loop through the vulnerabilities and filter based on severity
    for result in results:
        if "Vulnerabilities" in result:
            for vuln in result["Vulnerabilities"]:
                severity = vuln.get("Severity", "").upper()
                if severity in desired_severities:
                    filtered_vulnerabilities.append(
                        {
                            "VulnerabilityID": vuln.get("VulnerabilityID"),
                            "PkgName": vuln.get("PkgName"),
                            "InstalledVersion": vuln.get("InstalledVersion"),
                            "Severity": severity,
                            "Description": vuln.get("Description"),
                            "PrimaryURL": vuln.get("PrimaryURL"),
                        }
                    )

    # Save the filtered results to a new JSON file
    with open(output_file, "w", encoding="utf-8") as output_file:
        json.dump(filtered_vulnerabilities, output_file, indent=4)

    print(f"Filtered vulnerabilities saved to: {output_file}")


# Loop through each image and run the scan
for image in images_to_scan:
    image_name = image.split("/")[-1].replace(
        ":", "-"
    )  # Clean up image name for the output file
    output_file = f"/results/{image_name}-results.json"  # Define the output file path in the container

    # Build the complete docker command
    command = base_command + ["-o", output_file, image]

    # Print the command to be executed (for debugging)
    print(f"Running scan for image: {image}")
    print(f"Command: {' '.join(command)}")

    retries = 0

    while True:
        try:
            # Run the command
            if is_windows:
                # If on Windows, use shell=True to handle path differences
                subprocess.run(" ".join(command), shell=True, check=True)
            else:
                # On Linux/Mac, directly run the command
                subprocess.run(command, check=True)

            # If the scan succeeds, proceed to filtering
            print(f"Successfully scanned image: {image}")

            # Define input and output file paths for filtering
            result_file_path = os.path.join(results_dir, f"{image_name}-results.json")
            filtered_output_file_path = os.path.join(
                filtered_results_directory, f"filtered_{image_name}-results.json"
            )

            # Filter vulnerabilities and save to the filtered results directory
            filter_vulnerabilities(result_file_path, filtered_output_file_path)

            break  # Exit the retry loop on success

        except subprocess.CalledProcessError as e:
            retries += 1
            print(f"Error occurred while scanning {image}: {e}")

            # Check if the maximum number of retries has been reached
            if max_retries is not None and retries >= max_retries:
                print(f"Max retries reached for image: {image}. Skipping.")
                break

            # Wait for a specified delay before retrying
            print(
                f"Retrying in {retry_delay} seconds... (Attempt {retries}/{max_retries if max_retries else '∞'})"
            )
            time.sleep(retry_delay)
