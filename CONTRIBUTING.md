# Contributing to ThreatFade™

Thanks for your interest in ThreatFade! We welcome contributions from security researchers, developers, and the broader community.

## How to Contribute

### Reporting Issues

Found a bug? Have a feature request?

1. Check existing [issues](https://github.com/tinlance/threatfade/issues)
2. If not reported, open a new issue with:
   - Clear title and description
   - Steps to reproduce (for bugs)
   - Expected vs. actual behavior
   - Python version, OS, and environment details

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Add tests for new functionality (see `test_fade_engine.py`)
5. Ensure tests pass: `pytest test_fade_engine.py -v`
6. Commit with clear messages: `git commit -m "Add: Clear description of change"`
7. Push and submit a Pull Request

### Code Style

- **Python:** Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- **Comments:** Docstrings for all functions and classes
- **Type hints:** Use where applicable
- **Tests:** All new features should have tests

Example:
```python
def my_function(param1: str, param2: int) -> bool:
    """
    Short description of function.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    """
    pass
```

### Testing

Before submitting:

```bash
# Install dev dependencies
pip install -r requirements.txt
pip install pytest bandit

# Run tests
pytest test_fade_engine.py -v

# Security check
bandit -r core agents viz mitre volatility alerts
```

### Documentation

- Update README.md if changing user-facing behavior
- Add docstrings to all new functions
- Document configuration changes in comments

## Areas for Contribution

- **Q2 Priorities:**
  - Real pcap/traffic file analysis
  - Endpoint agents (Windows/Linux)
  - SIEM export formats (Splunk, ELK)
  - Performance optimizations
  
- **Always Welcome:**
  - Bug fixes
  - Test improvements
  - Documentation
  - Community feedback

## Community Guidelines

- Be respectful and inclusive
- Provide constructive feedback
- Assume good intent
- No harassment or discrimination

## Questions?

- Open an issue with `[QUESTION]` in title
- Check existing docs and README first

---

**Built with ❤️ by Tinlance Limited**  
Nigeria-1. World-0. 💚
