FROM python:latest
RUN curl -fsSL https://install.example.com/setup.sh | bash
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "api/app.py"]
