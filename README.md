# Calendar Full Stack Application

 

This repository contains a full stack application with a React frontend and a Flask backend. Follow the instructions below to set up and run the application.

 

## Prerequisites

 

Make sure you have the following installed on your machine:

 

- [Node.js](https://nodejs.org/) (version 14.x or later recommended)

- [npm](https://www.npmjs.com/) (comes with Node.js)

- [Python](https://www.python.org/) (version 3.8 or later)

- [pip](https://pip.pypa.io/)

- [Docker](https://www.docker.com/) (optional but recommended)

 

## Setup

 

### Option 1: Run with Docker

 

1. Clone the repository:

 

    ```sh

    git clone https://github.com/tejanidamni/CalendarApp.git

    cd CalendarApp

    ```

 

2. Build and run the Docker containers:

 

    ```sh

    docker-compose up --build

    ```

 

3. Access the applications:

 

    - React application: [http://localhost:3000](http://localhost:3000)

    - Flask application: [http://localhost:5000](http://localhost:5000)

 

### Option 2: Run Frontend and Backend Individually

 

#### Frontend: React Application

 

1. Navigate to the React application directory and install dependencies:

 

    ```sh

    cd frontend

    npm install

    ```

 

2. Start the development server:

 

    ```sh

    npm start

    ```

 

#### Backend: Flask Application

 

1. Navigate to the Flask application directory and create a virtual environment:

 

    ```sh

    cd backend

    python3 -m venv venv

    ```

 

2. Activate the virtual environment:

 

    - On Windows:

      ```sh

      venv\Scripts\activate

      ```

    - On macOS/Linux:

      ```sh

      source venv/bin/activate

      ```

 

3. Install dependencies:

 

    ```sh

    pip install -r requirements.txt

    ```

 

4. Run the Flask application:

 

    ```sh

    python3 ./app.py

    ```
