# Al-Sayyad - Advanced Antivirus Tool

![Al-Sayyad Logo](docs/logo.png) <!-- placeholder for a logo -->

**Al-Sayyad** is an advanced antivirus tool designed to provide comprehensive protection against a wide range of cyber threats. The tool combines signature-based and heuristic/behavioral detection techniques, along with real-time monitoring of the file system, processes, and network connections. It is developed using Python and features a professional, interactive, and user-friendly graphical interface in Arabic.

**by Hassan Mohamed Hassan Ahmed**

## Key Features

*   **Real-time Protection:** Continuous monitoring of the file system to detect suspicious activities.
*   **Multi-technique Scanning:** Combines:
    *   **Signature-Based Scanning:** Detects known malware using a database of hashes.
    *   **Heuristic & Behavioral Scanning:** Analyzes file and process behavior to detect new and unknown threats.
*   **Professional Graphical User Interface (GUI):** An interactive and easy-to-use dashboard to display protection status, initiate scans, and manage threats.
*   **Threat Management:** Quarantine suspicious files, restore them, or delete them permanently.
*   **Database Updates:** A mechanism to update the signature database to ensure protection against the latest threats.
*   **Statistics and Reports:** Displays charts and statistics on threat activity and scan operations.

## Architectural Structure

Al-Sayyad follows a modular architecture divided into key components to ensure efficiency and ease of maintenance:

*   **`src/core/`**: Contains the core logic of the tool such as the scanning engine (`scanner.py`), database manager (`database_manager.py`), real-time monitor (`real_time_monitor.py`), and signature updater (`updater.py`).
*   **`src/gui/`**: Contains the graphical interface components (`main_window.py`, `ui_elements.py`).
*   **`src/utils/`**: Contains utility functions such as file operations (`file_operations.py`) and system analyzer (`system_analyzer.py`).
*   **`data/`**: For storing the signature database (`signatures.db`) and quarantined files (`quarantine/`).
*   **`tests/`**: For unit tests of various components.

## Requirements

The tool requires Python 3.x and the following libraries:

*   `PyQt5`
*   `watchdog`
*   `pefile` (for Windows systems)
*   `psutil`
*   `SQLAlchemy`
*   `requests`
*   `pyqtgraph`
*   `matplotlib`

These libraries can be installed using `pip`:

```bash
pip install -r requirements.txt
```

## Installation and Running

To set up and run Al-Sayyad on your machine, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/kush-king249/Al-Sayyad.git
    cd Al-Sayyad
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the tool:**
    ```bash
    python src/main.py
    ```

    A splash screen will appear, followed by the main graphical interface of the tool.

## Usage

After launching the tool, the main dashboard will appear, providing an overview of the protection status and available actions:

*   **Main Status Screen:** Displays whether the system is protected or not, with a clear visual indicator.
*   **Quick Actions:** Buttons for "Quick Scan", "Full Scan", "Update", and "Quarantine".
*   **Threat Monitoring:** A chart showing threat activity over time.
*   **Notifications:** A panel displaying recent notifications about detected threats and scan operations.

### How to perform a scan:

1.  **Quick Scan:** Click the "Quick Scan" button to perform a scan of common folders (Desktop, Downloads, Documents).
2.  **Full Scan:** Click the "Full Scan" button and then select the folder you wish to scan completely.
3.  **Custom Folder Scan:** From the "File" menu, select "Scan Folder..." to choose any other folder for scanning.

### Quarantine:

When a threat is detected, it will be automatically moved to the quarantine folder. You can access "Quarantine" from the quick action buttons or from the "Tools" menu to manage quarantined files (restore or delete).

### Updates:

Click the "Update" button to check for and install new signature database updates.

## Documentation and Testing

*   **Code Documentation:** All functions and classes are documented using `docstrings` for easy understanding and maintenance.
*   **Unit Tests:** The project includes unit tests for core components (scanner engine, file operations, database manager) to ensure their proper functioning.
    Tests can be run from the `tests/` folder:
    ```bash
    python -m unittest discover tests
    ```

## Future Development Plan

*   **Improved Behavioral Detection:** Integrate machine learning techniques to enhance detection capabilities for unknown threats.
*   **Cross-Platform Support:** Extend support to other operating systems such as Linux and macOS.
*   **Real Update Server:** Develop a centralized update server to provide regular signature updates.
*   **Web Protection:** Add features for browsing protection against malicious websites.
*   **Firewall:** Integrate a simple firewall to monitor network traffic.

## Contribution

Contributions are welcome! If you wish to contribute to the development of Al-Sayyad, please open an `issue` or submit a `pull request` on the GitHub repository.

## Author

**Hassan Mohamed Hassan Ahmed**

[GitHub Profile](https://github.com/kush-king249)

---
