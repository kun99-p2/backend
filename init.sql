CREATE DATABASE IF NOT EXISTS toktik;
USE toktik;

-- Create the 'User' table
CREATE TABLE IF NOT EXISTS User (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- Create the 'Tokens' table
CREATE TABLE IF NOT EXISTS Tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    token VARCHAR(500) UNIQUE NOT NULL
);

-- Create the 'Video' table
CREATE TABLE IF NOT EXISTS Video (
    id VARCHAR(255) PRIMARY KEY NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL
);

-- Create the 'VLs' table
CREATE TABLE IF NOT EXISTS VLs (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    views INT DEFAULT 0,
    likes INT DEFAULT 0
);

-- Create the 'Comments' table
CREATE TABLE IF NOT EXISTS Comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    video_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    comment VARCHAR(255) NOT NULL,
    video_title VARCHAR(255) NOT NULL,
    timestamp VARCHAR(255) NOT NULL
);

-- Create the 'Notifications' table
CREATE TABLE IF NOT EXISTS Notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    video_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    notification VARCHAR(255) NOT NULL,
    video_title VARCHAR(255) NOT NULL,
    timestamp VARCHAR(255) NOT NULL,
    isRead BOOLEAN NOT NULL
);