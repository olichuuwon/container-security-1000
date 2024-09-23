import os
import subprocess
import platform

# Define the list of images to scan
images_to_scan = [
    "quay.io/jeslynlamxy/starchat-app:latest",
    "quay.io/jeslynlamxy/explorer-app:latest",
    "quay.io/jeslynlamxy/postgres-logging:latest",
    "quay.io/jeslynlamxy/ollama-llama-8b:latest",
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
    "image",  # Run the trivy image scanner
    "-f",
    "json",  # Output format
    "--scanners",
    "vuln",  # Scan for vulnerabilities
    "--timeout",
    "999m",  # Set timeout
]

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

    # Run the command
    try:
        if is_windows:
            # If on Windows, use shell=True to handle path differences
            subprocess.run(" ".join(command), shell=True, check=True)
        else:
            # On Linux/Mac, directly run the command
            subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while scanning {image}: {e}")
