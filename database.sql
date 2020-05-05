CREATE DATABASE verge;

CREATE TABLE Users
(
    id SERIAL PRIMARY KEY,
    role_id NUMERIC(50) NOT NULL DEFAULT 1,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    state VARCHAR(50),
    created_at VARCHAR(255)
);

CREATE TABLE Roles
(
    id SERIAL PRIMARY KEY,
    name VARCHAR(255)
)

INSERT INTO Roles
VALUES(1, 'user')

CREATE TABLE Parcel
(
    user_id SERIAL PRIMARY KEY,
    price NUMERIC(8) NOT NULL,
    weight NUMERIC(8) NOT NULL,
    location VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    sender_name VARCHAR(255) NOT NULL,
    sender_note VARCHAR(255) NOT NULL,
    status VARCHAR(255) NOT NULL DEFAULT 'Pending'
);

CREATE TABLE parcel
(
    id SERIAL PRIMARY KEY,
    user_id NUMERIC(50) NOT NULL DEFAULT 0,
    price NUMERIC(50) NOT NULL,
    weight VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    sender_name VARCHAR(255) NOT NULL,
    sender_note VARCHAR(255) NOT NULL,
    status VARCHAR(255) NOT NULL DEFAULT 'Pending'
);

