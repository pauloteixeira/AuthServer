CREATE TABLE `clinic` (
  id int unsigned NOT NULL AUTO_INCREMENT,
  name varchar(200) NOT NULL,
  cnpj varchar(14) NOT NULL,
  created_at datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;


CREATE TABLE profile (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(200) NOT NULL
);

CREATE TABLE user (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  clinic_id INT UNSIGNED NOT NULL,
  profile_id INT UNSIGNED NOT NULL,
  name VARCHAR(200) NOT NULL,
  email VARCHAR(150) NOT NULL,
  password CHAR(64) NOT NULL,
  created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
  is_active TINYINT(1) NULL DEFAULT 0,
  FOREIGN KEY (clinic_id) REFERENCES clinic(id) ON DELETE CASCADE,
  FOREIGN KEY (profile_id) REFERENCES profile(id) ON DELETE CASCADE
);

CREATE TABLE oauth_client (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  client_id VARCHAR(100) NOT NULL UNIQUE,
  client_secret VARCHAR(200) NOT NULL,
  redirect_uris TEXT NOT NULL, -- armazenar múltiplas URIs como JSON ou string separada por vírgula
  created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE authorization_code (
  code VARCHAR(100) NOT NULL PRIMARY KEY,
  client_id INT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  redirect_uri VARCHAR(500) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES oauth_client(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE access_token (
  token VARCHAR(255) NOT NULL PRIMARY KEY,
  client_id INT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  scope VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES oauth_client(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE TABLE refresh_token (
  token VARCHAR(255) NOT NULL PRIMARY KEY,
  client_id INT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  scope VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES oauth_client(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);


INSERT INTO profile (name) values ('Funcionário'),('Médico'),('Admin');
