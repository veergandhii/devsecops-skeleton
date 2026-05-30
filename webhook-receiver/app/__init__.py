# Marks this folder as a Python package so imports use this local app module.
#Python decides what a “package” is based on this file.
# Without it, Python might import a different app from somewhere else on your machine.
# Adding __init__.py tells Python: “this folder is the app package for this project.”
# That makes from app import config pull your code, not something else.