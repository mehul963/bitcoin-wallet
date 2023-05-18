#!/bin/bash

# Activate the virtual environment (if applicable)
# source /path/to/your/virtualenv/bin/activate


# Install requirements
echo "[BUILD STARTED]"
pip install -r requirements.txt
echo "[REQUIREMENTS INSTALLED]"
# Collect static files
python manage.py collectstatic --noinput

python manage.py makemigraions wallet
python manage.py migrate

echo "[BUILD SUCCESFULL]"
