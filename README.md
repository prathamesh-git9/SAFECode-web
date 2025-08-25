# SAFECode-Web - Version 1

A simple web application for analyzing C code security vulnerabilities and automatically fixing them using AI.

## Features

- **C Code Analysis**: Uses Flawfinder to detect security vulnerabilities in C code
- **AI-Powered Fixes**: Automatically fixes detected vulnerabilities using OpenAI's GPT
- **Web Interface**: Simple Flask-based web interface for easy interaction
- **Real-time Results**: Get analysis results and fixed code instantly

## Quick Start

### Prerequisites

- Python 3.11+
- Flawfinder (C/C++ static analysis tool)
- OpenAI API key

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/prathamesh-git9/SAFECode-web.git
   cd SAFECode-web
   ```

2. **Set up virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/Mac:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install flask openai flawfinder
   ```

4. **Set up environment variables**:
   Create a `.env` file with your OpenAI API key:
   ```
   OPENAI_API_KEY=your_openai_api_key_here
   ```

5. **Run the application**:
   ```bash
   python simple_web_app.py
   ```

6. **Access the web interface**:
   Open your browser and go to: `http://localhost:5000`

## Usage

1. **Paste C Code**: Enter your C code in the text area
2. **Analyze**: Click "Analyze Code" to find vulnerabilities
3. **Fix**: Click "Fix Code" to automatically fix detected issues
4. **View Results**: See the original vulnerabilities and the fixed code

## Example

### Input C Code:
```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char input[20] = "This is too long for buffer";
    strcpy(buffer, input);  // Buffer overflow vulnerability
    printf("Buffer: %s\n", buffer);
    return 0;
}
```

### Analysis Results:
- **CWE-120**: Buffer Overflow vulnerability detected
- **Line 8**: `strcpy(buffer, input);`
- **Severity**: High

### Fixed Code:
```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char input[20] = "This is too long for buffer";
    strncpy(buffer, input, sizeof(buffer) - 1);  // Safe copy with bounds checking
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    printf("Buffer: %s\n", buffer);
    return 0;
}
```

## Project Structure

```
SAFECode-web/
├── simple_web_app.py          # Main Flask web application
├── simple_sast_fixer.py       # Standalone SAST + Fix script
├── backend/                   # Full FastAPI backend (future versions)
├── frontend/                  # React frontend (future versions)
├── scripts/                   # Setup and startup scripts
├── tests/                     # Test corpus and verification tools
├── .github/                   # GitHub Actions CI/CD
└── README.md                  # This file
```

## Supported Vulnerability Types

- **CWE-120**: Buffer Overflow
- **CWE-134**: Format String Vulnerabilities
- **CWE-78**: Command Injection
- **CWE-190**: Integer Overflow
- **CWE-367**: Race Conditions
- And more...

## Configuration

### Environment Variables

- `OPENAI_API_KEY`: Your OpenAI API key (required for code fixing)
- `FLASK_ENV`: Set to 'development' for debug mode

### Flawfinder Configuration

The application uses Flawfinder with the following settings:
- CSV output format for easy parsing
- Context lines for better vulnerability understanding
- Data-only mode for clean output

## Development

### Running Tests

```bash
python tools/verify_against_api.py
```

### Adding New Features

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Version History

### Version 1.0 (Current)
- Simple Flask web interface
- Flawfinder integration for C code analysis
- OpenAI GPT integration for automatic code fixing
- Basic web UI with code input and results display

### Future Versions
- Full FastAPI backend with advanced features
- React frontend with enhanced UI
- Advanced suppression rules
- Baseline comparison
- Telemetry and metrics
- Docker deployment
- CI/CD pipeline

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any issues or have questions, please open an issue on GitHub.

## Acknowledgments

- [Flawfinder](https://dwheeler.com/flawfinder/) - C/C++ static analysis tool
- [OpenAI](https://openai.com/) - GPT API for code fixing
- [Flask](https://flask.palletsprojects.com/) - Web framework
