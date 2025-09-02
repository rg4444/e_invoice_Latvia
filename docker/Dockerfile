FROM python:3.12-slim
WORKDIR /app
COPY app /app
RUN pip install --no-cache-dir fastapi uvicorn[standard] jinja2 requests lxml python-dotenv
EXPOSE 9595
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9595"]
