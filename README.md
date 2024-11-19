
# Interactsh Python Client - OAST Platform

A Python-based client for interacting with the Interactsh OAST platform. This tool allows users to easily generate and manage interactions through DNS queries and HTTP callbacks.

## Features

- Interactive polling for DNS and HTTP-based interactions.
- Lightweight and easy to use with simple CLI options.
- Displays interaction results in real-time.

## Usage

### Command-line Options

To display the help menu:

```bash
python interactsh_client.py --help
```

#### Output:
```
usage: interactsh_client.py [-h] [-v]

Interactsh Python Client

options:
  -h, --help     show this help message and exit
  -v, --verbose  Enable verbose mode
```

### Example Usage

To run the client with verbose output enabled:

```bash
python interactsh_client.py -v
```

## Screenshot

Below is a sample screenshot of the client in action, polling for DNS interactions:

![image](https://github.com/user-attachments/assets/c6c95925-0fbe-4ba3-8681-9a9521c69054)


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/interactsh-client.git
   ```
2. Navigate to the project directory:
   ```bash
   cd interactsh-client
   ```
3. Run the client using Python:
   ```bash
   python interactsh_client.py
   ```

## License

This project is licensed under the [MIT License](LICENSE).
