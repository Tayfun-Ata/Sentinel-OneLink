# Sentinel_OneLink | Home Security Addition

## Project Structure
- `vision_dashboard.py`: Universal dashboard app (Windows installer, point-and-click)
- `network_guardian_agent/agent.py`: Dedicated agent for network-wide monitoring (bundled in installer or pre-configured image)

## Features
- One-click installer, no technical setup required
- Modern, easy-to-use dashboard UI
- Real-time network monitoring and defense
- Modular, future-proof architecture
- No manual Python, pip, or command line required

## Usage
1. Download and run the installer
2. Launch the dashboard app
3. Connect to your agent (auto-discovered)
4. Monitor and defend your network with simple clicks

## Notes
- All dependencies and configuration are bundled in the installer
- No code editing or technical steps required
- For support or upgrades, contact the developer

### Internal build notes
- Use `installer/build_dashboard.ps1` to generate the Windows-ready executable via PyInstaller.


