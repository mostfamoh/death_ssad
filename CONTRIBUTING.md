# Contributing to TP Cryptographie Classique

Thank you for your interest in contributing to this educational project!

## 🎯 Project Goals

This project is designed for **educational purposes only** to demonstrate:
- How classical cryptographic algorithms work
- Why they are insecure for modern use
- How attacks exploit these weaknesses
- Best practices for secure authentication

## 🛠️ How to Contribute

### Reporting Issues

If you find a bug or have a suggestion:
1. Check if the issue already exists
2. Create a new issue with:
   - Clear title
   - Detailed description
   - Steps to reproduce (if bug)
   - Expected vs actual behavior
   - Screenshots if applicable

### Suggesting Enhancements

Ideas for improvements:
- Additional classical ciphers (Vigenère, Rail Fence, etc.)
- More attack simulations
- Better visualization of results
- Additional languages support
- Documentation improvements

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/YourFeature`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**: `git commit -m "Add: Description of changes"`
6. **Push to your fork**: `git push origin feature/YourFeature`
7. **Open a Pull Request**

### Code Style

- Use clear, descriptive variable names
- Comment complex logic
- Follow existing code structure
- Keep functions focused and modular
- No external dependencies (keep it vanilla JS + Node.js standard lib)

### Testing Checklist

Before submitting:
- [ ] Server starts without errors
- [ ] Frontend loads correctly
- [ ] All 4 cipher algorithms work (encrypt/decrypt)
- [ ] Attack simulations execute successfully
- [ ] Results are logged to CSV
- [ ] No console errors in browser
- [ ] Code is commented and readable

## 📚 Educational Focus

Remember this is an **educational project**. Contributions should:
- ✅ Enhance learning value
- ✅ Demonstrate security concepts clearly
- ✅ Include explanations and documentation
- ✅ Show both vulnerable and secure approaches
- ❌ Not add production-grade security (that's not the point!)
- ❌ Not add complex dependencies

## 🔐 Security Note

This project intentionally demonstrates **insecure** cryptography. Do not:
- Submit PRs to "improve" security of classical ciphers
- Add features that could be misused for real attacks
- Remove educational warnings

## 📝 Documentation

Good documentation is crucial for education:
- Update README.md if adding features
- Add comments explaining algorithms
- Include examples in GUIDE_ATTAQUES.md
- Update report.md with theoretical background

## 🌐 Translations

We welcome translations! To add a new language:
1. Create `README.[lang].md`
2. Translate UI strings in `frontend/index.html`
3. Add language selector (optional)

## 💬 Questions?

Open an issue with the "question" label or reach out to maintainers.

---

**Thank you for helping make cryptography education better! 🔐📚**
