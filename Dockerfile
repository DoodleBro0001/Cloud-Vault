# Use an official lightweight Node.js engine
FROM node:20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package files first to optimize installation caching
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production

# Copy the rest of your application code
COPY . .

# Inform the container system which port to monitor
EXPOSE 3000

# Start your Express server
CMD ["node", "server.js"]