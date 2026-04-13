FROM fedora:41 AS builder

RUN dnf update -y && \
    dnf install -y gcc gcc-c++ cmake make systemd-devel && \
    dnf clean all

WORKDIR /build

COPY licgen/ ./licgen/

ARG APP_NAME="Prog"
ARG APP_SECRET

RUN cmake -S licgen -B licgen/build \
    -DLICGEN_APPLICATION_NAME="${APP_NAME}" \
    -DLICGEN_APPLICATION_SECRET="${APP_SECRET}" \
    -DLICGEN_BUILD_GENERATOR=ON \
    -DCMAKE_BUILD_TYPE=Release

RUN cmake --build licgen/build --target ${APP_NAME}-license-generator -j$(nproc)


FROM fedora:41

# Установка системных пакетов (как вы указали, DNF будет тянуть пакеты с локального зеркала компании)
RUN dnf update -y && \
    dnf install -y python3 python3-pip systemd-libs && \
    dnf clean all

WORKDIR /app

# Копируем список зависимостей и папку с заранее скачанными пакетами
COPY requirements.txt .
COPY pip_packages/ ./pip_packages/

# Устанавливаем пакеты СТРОГО из локальной папки без доступа к сети
# --no-index: запрещает обращаться к PyPI в интернете
# --find-links: указывает, где искать локальные файлы
RUN pip3 install --no-cache-dir --no-index --find-links=./pip_packages -r requirements.txt

# Опционально: удаляем скачанные архивы, чтобы уменьшить итоговый размер Docker-образа
RUN rm -rf ./pip_packages

# Копируем остальной код
COPY app.py .
COPY templates/ ./templates/

# Копируем собранный бинарник из стадии builder
COPY --from=builder /build/licgen/build/Prog-license-generator ./Prog-license-generator

RUN chmod +x Prog-license-generator
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 8010

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8010"]