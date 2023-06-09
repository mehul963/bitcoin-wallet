# Use the official Python base image with Python 3.9
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt file to the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install -U pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Django project code to the container
COPY . .

# Expose the port that Django runs on (default is 8000)
EXPOSE 8080

#  Start the Django development server
CMD ["python", "manage.py", "makemigrations","wallet"]
CMD ["python", "manage.py", "migrate"]
CMD ["python", "manage.py", "runserver","0.0.0.0:8080"]

