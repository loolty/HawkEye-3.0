-- Fictional Hawkeyes Optical demo records. Safe to run repeatedly.
-- These patients use example.test addresses so real people are not contacted.
USE hawkeye_database;
SET @branch_id := (SELECT id FROM branches WHERE name='Main Branch' LIMIT 1);

INSERT INTO patients (patient_id,name,birthdate,phone,email,address,channel,branch_id)
SELECT 'DEMO-1001','Maria Santos','1998-04-12','09170001001','maria.santos@example.test','Demo address 1','Email',@branch_id
WHERE NOT EXISTS (SELECT 1 FROM patients WHERE patient_id='DEMO-1001');
INSERT INTO patients (patient_id,name,birthdate,phone,email,address,channel,branch_id)
SELECT 'DEMO-1002','Joshua Reyes','1989-09-23','09170001002','joshua.reyes@example.test','Demo address 2','Email',@branch_id
WHERE NOT EXISTS (SELECT 1 FROM patients WHERE patient_id='DEMO-1002');
INSERT INTO patients (patient_id,name,birthdate,phone,email,address,channel,branch_id)
SELECT 'DEMO-1003','Angela Cruz','2001-01-08','09170001003','angela.cruz@example.test','Demo address 3','Email',@branch_id
WHERE NOT EXISTS (SELECT 1 FROM patients WHERE patient_id='DEMO-1003');
INSERT INTO patients (patient_id,name,birthdate,phone,email,address,channel,branch_id)
SELECT 'DEMO-1004','Daniel Garcia','1978-06-30','09170001004','daniel.garcia@example.test','Demo address 4','Email',@branch_id
WHERE NOT EXISTS (SELECT 1 FROM patients WHERE patient_id='DEMO-1004');

SET @maria := (SELECT id FROM patients WHERE patient_id='DEMO-1001' LIMIT 1);
SET @joshua := (SELECT id FROM patients WHERE patient_id='DEMO-1002' LIMIT 1);
SET @angela := (SELECT id FROM patients WHERE patient_id='DEMO-1003' LIMIT 1);
SET @daniel := (SELECT id FROM patients WHERE patient_id='DEMO-1004' LIMIT 1);

-- Today's appointments should be visible in the staff Dashboard action queue.
INSERT INTO appointments (patient_id,type,`date`,`time`,status,reminder_status,notes,request_only,branch_id)
SELECT @maria,'Eye check',DATE_FORMAT(CURDATE(),'%Y-%m-%d'),'11:00','Confirmed','Waiting','Demo appointment for dashboard',0,@branch_id
WHERE @maria IS NOT NULL AND NOT EXISTS (SELECT 1 FROM appointments WHERE patient_id=@maria AND type='Eye check' AND `date`=DATE_FORMAT(CURDATE(),'%Y-%m-%d') AND `time`='11:00');
INSERT INTO appointments (patient_id,type,`date`,`time`,status,reminder_status,notes,request_only,branch_id)
SELECT @joshua,'Eye check',DATE_FORMAT(CURDATE(),'%Y-%m-%d'),'13:30','Pending','Waiting','Demo appointment awaiting confirmation',0,@branch_id
WHERE @joshua IS NOT NULL AND NOT EXISTS (SELECT 1 FROM appointments WHERE patient_id=@joshua AND type='Eye check' AND `date`=DATE_FORMAT(CURDATE(),'%Y-%m-%d') AND `time`='13:30');

-- Follow-ups appear in the Follow-Ups module and dashboard counts.
INSERT INTO appointments (patient_id,type,`date`,`time`,status,reminder_status,notes,request_only,branch_id)
SELECT @angela,'Follow-up',DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 3 DAY),'%Y-%m-%d'),'10:00','Confirmed','Waiting','Demo follow-up after eye examination',0,@branch_id
WHERE @angela IS NOT NULL AND NOT EXISTS (SELECT 1 FROM appointments WHERE patient_id=@angela AND type='Follow-up' AND `date`=DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 3 DAY),'%Y-%m-%d') AND `time`='10:00');
INSERT INTO appointments (patient_id,type,`date`,`time`,status,reminder_status,notes,request_only,branch_id)
SELECT @daniel,'Prescription review',DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 7 DAY),'%Y-%m-%d'),'15:00','Pending','Waiting','Demo prescription review',0,@branch_id
WHERE @daniel IS NOT NULL AND NOT EXISTS (SELECT 1 FROM appointments WHERE patient_id=@daniel AND type='Prescription review' AND `date`=DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 7 DAY),'%Y-%m-%d') AND `time`='15:00');

-- Linked prescription records. reference is checked to keep repeated imports idempotent.
INSERT INTO prescriptions (patient_id,recorded,optometrist,od_sphere,od_cylinder,od_axis,od_add,od_pd,os_sphere,os_cylinder,os_axis,os_add,os_pd,notes,return_date,reference)
SELECT @maria,DATE_FORMAT(CURDATE(),'%Y-%m-%d'),'Dr. Paolo Garcia','-1.25','-0.50','180','0.00','31','-1.00','-0.25','175','0.00','31','Fictional demo prescription',DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 180 DAY),'%Y-%m-%d'),'DEMO-RX-1001'
WHERE @maria IS NOT NULL AND NOT EXISTS (SELECT 1 FROM prescriptions WHERE reference='DEMO-RX-1001');
INSERT INTO prescriptions (patient_id,recorded,optometrist,od_sphere,od_cylinder,od_axis,od_add,od_pd,os_sphere,os_cylinder,os_axis,os_add,os_pd,notes,return_date,reference)
SELECT @joshua,DATE_FORMAT(CURDATE(),'%Y-%m-%d'),'Dr. Paolo Garcia','-2.00','-0.75','170','0.00','32','-1.75','-0.50','175','0.00','32','Fictional demo prescription',DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 30 DAY),'%Y-%m-%d'),'DEMO-RX-1002'
WHERE @joshua IS NOT NULL AND NOT EXISTS (SELECT 1 FROM prescriptions WHERE reference='DEMO-RX-1002');
INSERT INTO prescriptions (patient_id,recorded,optometrist,od_sphere,od_cylinder,od_axis,od_add,od_pd,os_sphere,os_cylinder,os_axis,os_add,os_pd,notes,return_date,reference)
SELECT @angela,DATE_FORMAT(CURDATE(),'%Y-%m-%d'),'Dr. Paolo Garcia','-0.75','-0.25','180','0.00','30','-0.50','-0.25','175','0.00','30','Fictional demo prescription',DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 3 DAY),'%Y-%m-%d'),'DEMO-RX-1003'
WHERE @angela IS NOT NULL AND NOT EXISTS (SELECT 1 FROM prescriptions WHERE reference='DEMO-RX-1003');
INSERT INTO prescriptions (patient_id,recorded,optometrist,od_sphere,od_cylinder,od_axis,od_add,od_pd,os_sphere,os_cylinder,os_axis,os_add,os_pd,notes,return_date,reference)
SELECT @daniel,DATE_FORMAT(CURDATE(),'%Y-%m-%d'),'Dr. Paolo Garcia','+1.00','-0.25','90','+1.50','32','+1.25','-0.25','85','+1.50','32','Fictional demo prescription',DATE_FORMAT(DATE_ADD(CURDATE(),INTERVAL 7 DAY),'%Y-%m-%d'),'DEMO-RX-1004'
WHERE @daniel IS NOT NULL AND NOT EXISTS (SELECT 1 FROM prescriptions WHERE reference='DEMO-RX-1004');

SELECT 'Patients' AS item, COUNT(*) AS rows_added_or_present FROM patients WHERE patient_id LIKE 'DEMO-%'
UNION ALL SELECT 'Appointments', COUNT(*) FROM appointments WHERE notes LIKE 'Demo %'
UNION ALL SELECT 'Prescriptions', COUNT(*) FROM prescriptions WHERE reference LIKE 'DEMO-RX-%';
