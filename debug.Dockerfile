FROM power-logger:latest

# Install strace for debugging
RUN apt-get update && apt-get install -y strace && rm -rf /var/lib/apt/lists/*

# Create enhanced debugging script
RUN echo '#!/bin/bash \n\
echo "Environment variables:" \n\
env \n\
echo "\nFile listing:" \n\
ls -la /app \n\
ls -la /app/config \n\
ls -la /app/data \n\
ls -la /app/logs \n\
echo "\nRunning with strace to find missing files:" \n\
export RUST_BACKTRACE=1 \n\
strace -ff -e trace=file /app/power-logger 2>&1 | grep -i "no such file"' > /app/debug.sh && \
    chmod +x /app/debug.sh

# Run the enhanced debugging script
CMD ["/app/debug.sh"] 