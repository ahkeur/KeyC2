# KeyC2

A secure web application for managing and tracking authentication tokens used in stage0 deployment.

> **Note**: This project is primarily designed for Windows. Linux users can make it work with minor modifications to the build process, but Windows is recommended for the best experience.

> **Disclaimer**: This is a Proof of Concept (PoC) implementing a keying system for stage0 payloads, inspired by an idea shared on LinkedIn. It is intended for educational and research purposes only.

## Features

- Stage0 creation through payload upload
- Real-time token monitoring
- Token status tracking (Pending, Registered, Blacklisted)
- Token management (Download, Blacklist/Unblacklist, Delete)
- Modern interface with dark mode support
- Secure authentication and file validation

## Prerequisites

- Python 3.8+
- pip
- MinGW/GCC

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ahkeur/keyc2.git
cd keyc2
```

2. Create a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate     
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Launch the application:
```bash
python main.py
```

## Usage

1. Access the interface at `http://localhost:8000`
2. Create a new Stage0 by uploading a .bin/.raw file
3. Manage tokens through the interface:
   - Download stage0
   - Blacklist/Unblacklist tokens
   - Delete tokens

## Security

- File validation (10MB max, .bin/.raw format)
- Secure token signatures
- Blacklist system
- Request validation

## License

This project is licensed under the MIT License. 