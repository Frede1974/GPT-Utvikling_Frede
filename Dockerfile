# Use the official Node.js 18 LTS Alpine image as the base
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Install app dependencies
# Copy only the package.json and package-lock.json files to install dependencies first
COPY package*.json ./
RUN npm install --production

# Copy the rest of the application code
COPY . .

# The app binds to port 8080 inside the container. Expose it so Fly.io can forward traffic.
EXPOSE 8080

# Define the default command to run the application. Use `node app.js` to start the Express server.
CMD ["node", "app.js"]