-- HawkEye Optical Clinic MySQL/MariaDB schema (database: hawkeye_database)

CREATE DATABASE IF NOT EXISTS hawkeye_database CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE hawkeye_database;



CREATE TABLE IF NOT EXISTS users (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255) UNIQUE,
 password VARCHAR(255), role VARCHAR(50), status VARCHAR(30) DEFAULT 'Active',
 email_verified TINYINT DEFAULT 1, reset_token VARCHAR(255), branch_id INT NULL,
 mfa_enabled TINYINT NOT NULL DEFAULT 0, mfa_secret VARCHAR(64) NULL, mfa_last_step BIGINT NULL, google_sub VARCHAR(64) NULL,
 UNIQUE KEY uniq_users_google_sub (google_sub)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS branches (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) UNIQUE, address TEXT,
 active TINYINT DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS patients (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id VARCHAR(100) UNIQUE, name VARCHAR(255),
 birthdate VARCHAR(30), phone VARCHAR(60), email VARCHAR(255), address TEXT,
 channel VARCHAR(30) DEFAULT 'Email', user_id INT NULL, branch_id INT NULL,
 INDEX idx_patients_name(name), INDEX idx_patients_branch(branch_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS prescriptions (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT, recorded VARCHAR(30), optometrist VARCHAR(255),
 od_sphere VARCHAR(30), od_cylinder VARCHAR(30), od_axis VARCHAR(30), od_add VARCHAR(30), od_pd VARCHAR(30),
 os_sphere VARCHAR(30), os_cylinder VARCHAR(30), os_axis VARCHAR(30), os_add VARCHAR(30), os_pd VARCHAR(30),
 notes TEXT, return_date VARCHAR(30), reference VARCHAR(100), INDEX idx_prescriptions_patient(patient_id),
 INDEX idx_prescriptions_return_date(return_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS appointments (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT, type VARCHAR(80), `date` VARCHAR(30), `time` VARCHAR(30),
 status VARCHAR(40), reminder_status VARCHAR(40), notes TEXT, request_only TINYINT DEFAULT 0, branch_id INT NULL, doctor_id INT NULL,
 INDEX idx_appointments_date(`date`), INDEX idx_appointments_patient(patient_id), INDEX idx_appointments_type(type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reminders (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT, appointment_id INT NULL, channel VARCHAR(30),
 message TEXT, sent_date VARCHAR(30), status VARCHAR(30), read_status VARCHAR(30) DEFAULT 'Unread',
 INDEX idx_reminders_patient(patient_id), INDEX idx_reminders_appointment(appointment_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_requests (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255), password VARCHAR(255),
 status VARCHAR(30) DEFAULT 'Pending', name VARCHAR(255), role VARCHAR(50) DEFAULT 'Clinic Staff', created_at VARCHAR(30)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id INT, action VARCHAR(255), entity VARCHAR(100),
 entity_id INT, created_at VARCHAR(30), INDEX idx_audit_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS patient_sessions (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT NOT NULL, visit_date VARCHAR(30) NOT NULL,
 visit_type VARCHAR(80) NOT NULL DEFAULT 'Eye check', notes TEXT, outcome VARCHAR(255), recorded_by INT,
 created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 INDEX idx_sessions_patient(patient_id), INDEX idx_sessions_date(visit_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS patient_reviews (
 patient_id INT NOT NULL PRIMARY KEY, reviewed_by INT, reviewed_at VARCHAR(30)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS clinic_chat_messages (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, patient_id INT NOT NULL, staff_id INT NOT NULL,
 message TEXT NOT NULL, created_at VARCHAR(30) NOT NULL, read_status VARCHAR(30) DEFAULT 'Unread',
 sender VARCHAR(20) NOT NULL DEFAULT 'Staff',
 INDEX idx_chat_patient(patient_id), INDEX idx_chat_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS email_tokens (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id INT, token_hash VARCHAR(255), expires_at VARCHAR(30), used TINYINT DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS pending_signups (
 email VARCHAR(255) NOT NULL PRIMARY KEY, name VARCHAR(255) NOT NULL, password_hash VARCHAR(255) NOT NULL,
 patient_id VARCHAR(100), birthdate VARCHAR(30), code_hash VARCHAR(255) NOT NULL, expires_at VARCHAR(30) NOT NULL,
 attempts INT NOT NULL DEFAULT 0, created_at VARCHAR(30) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
 id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, code_hash VARCHAR(64) NOT NULL,
 used TINYINT NOT NULL DEFAULT 0, INDEX idx_mfa_backup_user(user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limits (
 key_hash VARCHAR(64) NOT NULL PRIMARY KEY, hits INT NOT NULL DEFAULT 0, window_start VARCHAR(30) NOT NULL,
 locked_until VARCHAR(30) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
