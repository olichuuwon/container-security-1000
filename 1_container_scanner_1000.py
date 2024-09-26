import os
import subprocess
import platform
import time

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

            # If the scan succeeds, break out of the retry loop
            print(f"Successfully scanned image: {image}")
            break

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
