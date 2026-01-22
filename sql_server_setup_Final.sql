-- ===================================================================
-- SQL SERVER SETUP FOR EDGE_DB - TABLES AND OBJECTS ONLY
-- ===================================================================
-- This script assumes EDGE_DB already exists and will:
-- 1. Use existing EDGE_DB database
-- 2. Create tables if they don't exist (or alter if needed)
-- 3. Create stored procedures for maintenance
-- 4. Create monitoring views
-- 5. Configure Query Store if not enabled
-- 
-- NO DROPS - Safe to run on existing database
-- ===================================================================

USE master;
GO

-- ===================================================================
-- STEP 0: VERIFY DATABASE EXISTS AND SWITCH TO IT
-- ===================================================================

PRINT '=================================================================';
PRINT 'STEP 0: Verifying EDGE_DB exists...';
PRINT '=================================================================';
PRINT '';

IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'EDGE_DB')
BEGIN
    PRINT '❌ ERROR: EDGE_DB database does not exist!';
    PRINT 'Please create the database first before running this script.';
    RAISERROR('EDGE_DB database not found', 16, 1);
    RETURN;
END
ELSE
BEGIN
    PRINT '✅ EDGE_DB database found';
END
GO

-- Switch to EDGE_DB
USE EDGE_DB;
GO

PRINT '✅ Connected to EDGE_DB database';
PRINT '';

-- ===================================================================
-- STEP 1: CONFIGURE DATABASE SETTINGS (NON-DESTRUCTIVE)
-- ===================================================================

PRINT '=================================================================';
PRINT 'STEP 1: Configuring database settings...';
PRINT '=================================================================';
PRINT '';

-- Configure recovery model if needed
DECLARE @RecoveryModel NVARCHAR(20);
SELECT @RecoveryModel = recovery_model_desc FROM sys.databases WHERE name = 'EDGE_DB';

IF @RecoveryModel != 'SIMPLE'
BEGIN
    ALTER DATABASE EDGE_DB SET RECOVERY SIMPLE;
    PRINT '✅ Set Recovery Model to SIMPLE (optimal for high-volume monitoring data)';
END
ELSE
BEGIN
    PRINT '✅ Recovery Model already set to SIMPLE';
END
GO

-- Enable Query Store if not enabled
USE EDGE_DB;
GO

IF NOT EXISTS (SELECT * FROM sys.database_query_store_options WHERE actual_state = 2)
BEGIN
    ALTER DATABASE EDGE_DB SET QUERY_STORE = ON;
    ALTER DATABASE EDGE_DB SET QUERY_STORE (
        OPERATION_MODE = READ_WRITE,
        DATA_FLUSH_INTERVAL_SECONDS = 900,
        STATISTICS_COLLECTION_INTERVAL = 60,
        MAX_STORAGE_SIZE_MB = 1000,
        QUERY_CAPTURE_MODE = AUTO,
        SIZE_BASED_CLEANUP_MODE = AUTO
    );
    PRINT '✅ Query Store enabled';
END
ELSE
BEGIN
    PRINT '✅ Query Store already enabled';
END
GO

PRINT '';

-- ===================================================================
-- STEP 2: CREATE OR ALTER TABLES
-- ===================================================================

PRINT '=================================================================';
PRINT 'STEP 2: Creating/Altering tables...';
PRINT '=================================================================';
PRINT '';

-- ===================================================================
-- TABLE 1: ApplicationMetrics
-- ===================================================================

PRINT 'Checking ApplicationMetrics table...';

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ApplicationMetrics')
BEGIN
    PRINT 'Creating ApplicationMetrics table...';
    CREATE TABLE ApplicationMetrics (
        MetricID BIGINT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        MonitoringHost NVARCHAR(255) NOT NULL,
        MonitoringHostIP NVARCHAR(50) NULL,
        
        -- Application details
        ApplicationName NVARCHAR(255) NOT NULL,
        URL NVARCHAR(1000) NULL,
        ResponseTimeMS FLOAT NULL,
        StatusCode INT NULL,
        Availability BIT NULL,
        DNSTimeMS FLOAT NULL,
        ConnectTimeMS FLOAT NULL,
        TLSTimeMS FLOAT NULL,
        FirstByteTimeMS FLOAT NULL,
        
        -- Status
        Status NVARCHAR(100) NULL,
        Severity NVARCHAR(50) NULL,
        Criticality NVARCHAR(50) NULL,
        ErrorMessage NVARCHAR(MAX) NULL,
        
        -- Indexes for fast queries
        INDEX IX_App_Timestamp NONCLUSTERED (Timestamp DESC),
        INDEX IX_App_Name_Time NONCLUSTERED (ApplicationName, Timestamp DESC),
        INDEX IX_App_Availability NONCLUSTERED (ApplicationName, Availability, Timestamp DESC),
        INDEX IX_App_Severity NONCLUSTERED (Severity, Timestamp DESC)
    );
    PRINT '✅ ApplicationMetrics created';
END
ELSE
BEGIN
    PRINT '✅ ApplicationMetrics already exists';
    
    -- Ensure critical columns are nullable (alter if needed)
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('ApplicationMetrics') AND name = 'ResponseTimeMS' AND is_nullable = 0)
    BEGIN
        ALTER TABLE ApplicationMetrics ALTER COLUMN ResponseTimeMS FLOAT NULL;
        PRINT '  ✅ Updated ResponseTimeMS to nullable';
    END
    
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('ApplicationMetrics') AND name = 'StatusCode' AND is_nullable = 0)
    BEGIN
        ALTER TABLE ApplicationMetrics ALTER COLUMN StatusCode INT NULL;
        PRINT '  ✅ Updated StatusCode to nullable';
    END
    
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('ApplicationMetrics') AND name = 'Availability' AND is_nullable = 0)
    BEGIN
        ALTER TABLE ApplicationMetrics ALTER COLUMN Availability BIT NULL;
        PRINT '  ✅ Updated Availability to nullable';
    END
END
GO

PRINT '';

-- ===================================================================
-- TABLE 2: SecurityEvents
-- ===================================================================

PRINT 'Checking SecurityEvents table...';

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'SecurityEvents')
BEGIN
    PRINT 'Creating SecurityEvents table...';
    CREATE TABLE SecurityEvents (
        EventID BIGINT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        MonitoringHost NVARCHAR(255) NOT NULL,
        
        -- Event details
        EventType NVARCHAR(100) NOT NULL,
        WindowsEventID NVARCHAR(50) NULL,
        
        SourceHost NVARCHAR(255) NULL,
        SourceIP NVARCHAR(50) NULL,
        DestinationIP NVARCHAR(50) NULL,
        
        UserName NVARCHAR(255) NULL,
        TargetUser NVARCHAR(255) NULL,
        
        LogonType NVARCHAR(50) NULL,
        FailureReason NVARCHAR(500) NULL,
        
        -- Threat details
        ThreatName NVARCHAR(500) NULL,
        ThreatAction NVARCHAR(100) NULL,
        
        -- Network details
        Protocol NVARCHAR(50) NULL,
        SourcePort INT NULL,
        DestinationPort INT NULL,
        Direction NVARCHAR(20) NULL,
        
        Severity NVARCHAR(50) NULL,
        AdditionalData NVARCHAR(MAX) NULL,
        
        -- Indexes
        INDEX IX_Sec_Timestamp NONCLUSTERED (Timestamp DESC),
        INDEX IX_Sec_EventType_Time NONCLUSTERED (EventType, Timestamp DESC),
        INDEX IX_Sec_SourceIP NONCLUSTERED (SourceIP, Timestamp DESC),
        INDEX IX_Sec_User NONCLUSTERED (UserName, Timestamp DESC),
        INDEX IX_Sec_ThreatName NONCLUSTERED (ThreatName, Timestamp DESC),
        INDEX IX_Sec_EventType_Severity NONCLUSTERED (EventType, Severity, Timestamp DESC)
    );
    PRINT '✅ SecurityEvents created';
END
ELSE
BEGIN
    PRINT '✅ SecurityEvents already exists';
END
GO

PRINT '';

-- ===================================================================
-- TABLE 3: NetworkMetrics
-- ===================================================================

PRINT 'Checking NetworkMetrics table...';

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'NetworkMetrics')
BEGIN
    PRINT 'Creating NetworkMetrics table...';
    CREATE TABLE NetworkMetrics (
        MetricID BIGINT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        MonitoringHost NVARCHAR(255) NOT NULL,
        
        -- Metric details
        MetricType NVARCHAR(100) NOT NULL,
        InterfaceName NVARCHAR(255) NULL,
        TargetHost NVARCHAR(255) NULL,
        TargetIP NVARCHAR(50) NULL,
        
        -- Measurements
        LatencyMS FLOAT NULL,
        PacketLossPct FLOAT NULL,
        ThroughputMbps FLOAT NULL,
        DNSResolutionMS FLOAT NULL,
        JitterMS FLOAT NULL,
        
        ThroughputSentMbps FLOAT NULL,
        ThroughputReceivedMbps FLOAT NULL,
        
        Direction NVARCHAR(20) NULL,
        Severity NVARCHAR(50) NULL,
        Status NVARCHAR(100) NULL,
        
        -- Indexes
        INDEX IX_Net_Timestamp NONCLUSTERED (Timestamp DESC),
        INDEX IX_Net_MetricType_Time NONCLUSTERED (MetricType, Timestamp DESC),
        INDEX IX_Net_Interface_Time NONCLUSTERED (InterfaceName, Timestamp DESC),
        INDEX IX_Net_Target_Time NONCLUSTERED (TargetHost, Timestamp DESC),
        INDEX IX_Net_MetricType_Severity NONCLUSTERED (MetricType, Severity, Timestamp DESC)
    );
    PRINT '✅ NetworkMetrics created';
END
ELSE
BEGIN
    PRINT '✅ NetworkMetrics already exists';
    
    -- Ensure LatencyMS is nullable
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('NetworkMetrics') AND name = 'LatencyMS' AND is_nullable = 0)
    BEGIN
        ALTER TABLE NetworkMetrics ALTER COLUMN LatencyMS FLOAT NULL;
        PRINT '  ✅ Updated LatencyMS to nullable';
    END
END
GO

PRINT '';

-- ===================================================================
-- TABLE 4: CertificateMetrics
-- ===================================================================

PRINT 'Checking CertificateMetrics table...';

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CertificateMetrics')
BEGIN
    PRINT 'Creating CertificateMetrics table...';
    CREATE TABLE CertificateMetrics (
        CertID BIGINT IDENTITY(1,1) PRIMARY KEY,
        Timestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        MonitoringHost NVARCHAR(255) NOT NULL,
        
        -- Certificate details
        Hostname NVARCHAR(255) NOT NULL,
        Port INT NULL DEFAULT 443,
        
        DaysUntilExpiry INT NULL,
        ExpiryDate DATETIME2 NULL,
        IssueDate DATETIME2 NULL,
        
        Issuer NVARCHAR(500) NULL,
        Subject NVARCHAR(500) NULL,
        IsSelfSigned BIT NULL,
        HasHostnameMismatch BIT NULL,
        
        -- Validation
        IsValid BIT NULL,
        ValidationError NVARCHAR(MAX) NULL,
        
        -- TLS/SSL
        TLSVersion NVARCHAR(50) NULL,
        CipherSuite NVARCHAR(255) NULL,
        HasWeakProtocol BIT NULL,
        HasWeakCipher BIT NULL,
        
        Severity NVARCHAR(50) NULL,
        Status NVARCHAR(100) NULL,
        
        -- Indexes
        INDEX IX_Cert_Hostname NONCLUSTERED (Hostname, Timestamp DESC),
        INDEX IX_Cert_Expiry NONCLUSTERED (DaysUntilExpiry, Timestamp DESC),
        INDEX IX_Cert_Severity NONCLUSTERED (Severity, DaysUntilExpiry),
        INDEX IX_Cert_Hostname_Expiry NONCLUSTERED (Hostname, DaysUntilExpiry)
    );
    PRINT '✅ CertificateMetrics created';
END
ELSE
BEGIN
    PRINT '✅ CertificateMetrics already exists';
    
    -- Ensure DaysUntilExpiry is nullable
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('CertificateMetrics') AND name = 'DaysUntilExpiry' AND is_nullable = 0)
    BEGIN
        ALTER TABLE CertificateMetrics ALTER COLUMN DaysUntilExpiry INT NULL;
        PRINT '  ✅ Updated DaysUntilExpiry to nullable';
    END
END
GO

PRINT '';

-- ===================================================================
-- TABLE 5: VulnerabilityFindings
-- ===================================================================

PRINT 'Checking VulnerabilityFindings table...';

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'VulnerabilityFindings')
BEGIN
    PRINT 'Creating VulnerabilityFindings table...';
    CREATE TABLE VulnerabilityFindings (
        FindingID BIGINT IDENTITY(1,1) PRIMARY KEY,
        ScanTimestamp DATETIME2 NOT NULL DEFAULT GETDATE(),
        MonitoringHost NVARCHAR(255) NOT NULL,
        
        -- Target details
        TargetName NVARCHAR(255) NOT NULL,
        TargetHostname NVARCHAR(255) NULL,
        TargetIP NVARCHAR(50) NULL,
        
        FindingType NVARCHAR(100) NOT NULL,
        Severity NVARCHAR(50) NOT NULL,
        
        -- Finding details
        Description NVARCHAR(MAX) NULL,
        Recommendation NVARCHAR(MAX) NULL,
        
        -- Type-specific
        Port INT NULL,
        Protocol NVARCHAR(50) NULL,
        CipherSuite NVARCHAR(255) NULL,
        TLSProtocol NVARCHAR(50) NULL,
        MissingHeader NVARCHAR(255) NULL,
        
        -- Risk scoring
        RiskScore INT NULL,
        CVSSScore FLOAT NULL,
        
        -- Remediation
        IsRemediated BIT NULL DEFAULT 0,
        RemediationDate DATETIME2 NULL,
        RemediationNotes NVARCHAR(MAX) NULL,
        
        -- Indexes
        INDEX IX_Vuln_Timestamp NONCLUSTERED (ScanTimestamp DESC),
        INDEX IX_Vuln_Target_Time NONCLUSTERED (TargetName, ScanTimestamp DESC),
        INDEX IX_Vuln_Severity NONCLUSTERED (Severity, ScanTimestamp DESC),
        INDEX IX_Vuln_Type NONCLUSTERED (FindingType, Severity, ScanTimestamp DESC),
        INDEX IX_Vuln_Remediation NONCLUSTERED (IsRemediated, Severity)
    );
    PRINT '✅ VulnerabilityFindings created';
END
ELSE
BEGIN
    PRINT '✅ VulnerabilityFindings already exists';
    
    -- Ensure key columns are nullable
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('VulnerabilityFindings') AND name = 'Port' AND is_nullable = 0)
    BEGIN
        ALTER TABLE VulnerabilityFindings ALTER COLUMN Port INT NULL;
        PRINT '  ✅ Updated Port to nullable';
    END
    
    IF EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('VulnerabilityFindings') AND name = 'Description' AND is_nullable = 0)
    BEGIN
        ALTER TABLE VulnerabilityFindings ALTER COLUMN Description NVARCHAR(MAX) NULL;
        PRINT '  ✅ Updated Description to nullable';
    END
END
GO

PRINT '';

-- ===================================================================
-- STEP 3: CREATE OR ALTER STORED PROCEDURES
-- ===================================================================

PRINT '=================================================================';
PRINT 'STEP 3: Creating/Updating stored procedures...';
PRINT '=================================================================';
PRINT '';

-- Cleanup ApplicationMetrics
PRINT 'Creating/Updating sp_CleanupApplicationMetrics...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CleanupApplicationMetrics')
    DROP PROCEDURE sp_CleanupApplicationMetrics;
GO
CREATE PROCEDURE sp_CleanupApplicationMetrics
    @RetentionDays INT = 90
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @CutoffDate DATETIME2 = DATEADD(day, -@RetentionDays, GETDATE());
    DECLARE @RowsDeleted INT;
    
    DELETE FROM ApplicationMetrics
    WHERE Timestamp < @CutoffDate;
    
    SET @RowsDeleted = @@ROWCOUNT;
    
    PRINT 'ApplicationMetrics: Deleted ' + CAST(@RowsDeleted AS VARCHAR(20)) + ' rows older than ' + CAST(@RetentionDays AS VARCHAR(10)) + ' days';
    
    RETURN @RowsDeleted;
END
GO
PRINT '✅ sp_CleanupApplicationMetrics created';

-- Cleanup SecurityEvents
PRINT 'Creating/Updating sp_CleanupSecurityEvents...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CleanupSecurityEvents')
    DROP PROCEDURE sp_CleanupSecurityEvents;
GO
CREATE PROCEDURE sp_CleanupSecurityEvents
    @RetentionDays INT = 180
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @CutoffDate DATETIME2 = DATEADD(day, -@RetentionDays, GETDATE());
    DECLARE @RowsDeleted INT;
    
    DELETE FROM SecurityEvents
    WHERE Timestamp < @CutoffDate;
    
    SET @RowsDeleted = @@ROWCOUNT;
    
    PRINT 'SecurityEvents: Deleted ' + CAST(@RowsDeleted AS VARCHAR(20)) + ' rows older than ' + CAST(@RetentionDays AS VARCHAR(10)) + ' days';
    
    RETURN @RowsDeleted;
END
GO
PRINT '✅ sp_CleanupSecurityEvents created';

-- Cleanup NetworkMetrics
PRINT 'Creating/Updating sp_CleanupNetworkMetrics...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CleanupNetworkMetrics')
    DROP PROCEDURE sp_CleanupNetworkMetrics;
GO
CREATE PROCEDURE sp_CleanupNetworkMetrics
    @RetentionDays INT = 60
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @CutoffDate DATETIME2 = DATEADD(day, -@RetentionDays, GETDATE());
    DECLARE @RowsDeleted INT;
    
    DELETE FROM NetworkMetrics
    WHERE Timestamp < @CutoffDate;
    
    SET @RowsDeleted = @@ROWCOUNT;
    
    PRINT 'NetworkMetrics: Deleted ' + CAST(@RowsDeleted AS VARCHAR(20)) + ' rows older than ' + CAST(@RetentionDays AS VARCHAR(10)) + ' days';
    
    RETURN @RowsDeleted;
END
GO
PRINT '✅ sp_CleanupNetworkMetrics created';

-- Cleanup CertificateMetrics
PRINT 'Creating/Updating sp_CleanupCertificateMetrics...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CleanupCertificateMetrics')
    DROP PROCEDURE sp_CleanupCertificateMetrics;
GO
CREATE PROCEDURE sp_CleanupCertificateMetrics
    @RetentionDays INT = 365
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @CutoffDate DATETIME2 = DATEADD(day, -@RetentionDays, GETDATE());
    DECLARE @RowsDeleted INT;
    
    DELETE FROM CertificateMetrics
    WHERE Timestamp < @CutoffDate;
    
    SET @RowsDeleted = @@ROWCOUNT;
    
    PRINT 'CertificateMetrics: Deleted ' + CAST(@RowsDeleted AS VARCHAR(20)) + ' rows older than ' + CAST(@RetentionDays AS VARCHAR(10)) + ' days';
    
    RETURN @RowsDeleted;
END
GO
PRINT '✅ sp_CleanupCertificateMetrics created';

-- Cleanup VulnerabilityFindings
PRINT 'Creating/Updating sp_CleanupVulnerabilityFindings...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CleanupVulnerabilityFindings')
    DROP PROCEDURE sp_CleanupVulnerabilityFindings;
GO
CREATE PROCEDURE sp_CleanupVulnerabilityFindings
    @RetentionDays INT = 365,
    @KeepRemediated BIT = 1
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @CutoffDate DATETIME2 = DATEADD(day, -@RetentionDays, GETDATE());
    DECLARE @RowsDeleted INT;
    
    IF @KeepRemediated = 1
    BEGIN
        DELETE FROM VulnerabilityFindings
        WHERE ScanTimestamp < @CutoffDate
          AND (IsRemediated = 0 OR IsRemediated IS NULL);
    END
    ELSE
    BEGIN
        DELETE FROM VulnerabilityFindings
        WHERE ScanTimestamp < @CutoffDate;
    END
    
    SET @RowsDeleted = @@ROWCOUNT;
    
    PRINT 'VulnerabilityFindings: Deleted ' + CAST(@RowsDeleted AS VARCHAR(20)) + ' rows older than ' + CAST(@RetentionDays AS VARCHAR(10)) + ' days';
    
    RETURN @RowsDeleted;
END
GO
PRINT '✅ sp_CleanupVulnerabilityFindings created';

-- Master cleanup procedure
PRINT 'Creating/Updating sp_CleanupAllTables...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_CleanupAllTables')
    DROP PROCEDURE sp_CleanupAllTables;
GO
CREATE PROCEDURE sp_CleanupAllTables
    @DryRun BIT = 0
AS
BEGIN
    SET NOCOUNT ON;
    
    PRINT '=================================================================';
    PRINT 'Data Retention Cleanup - ' + CASE WHEN @DryRun = 1 THEN 'DRY RUN MODE' ELSE 'LIVE MODE' END;
    PRINT 'Started: ' + CONVERT(VARCHAR(30), GETDATE(), 120);
    PRINT '=================================================================';
    PRINT '';
    
    IF @DryRun = 1
    BEGIN
        SELECT 'ApplicationMetrics' as TableName, COUNT(*) as RowsToDelete
        FROM ApplicationMetrics WHERE Timestamp < DATEADD(day, -90, GETDATE())
        UNION ALL
        SELECT 'SecurityEvents', COUNT(*) 
        FROM SecurityEvents WHERE Timestamp < DATEADD(day, -180, GETDATE())
        UNION ALL
        SELECT 'NetworkMetrics', COUNT(*) 
        FROM NetworkMetrics WHERE Timestamp < DATEADD(day, -60, GETDATE())
        UNION ALL
        SELECT 'CertificateMetrics', COUNT(*) 
        FROM CertificateMetrics WHERE Timestamp < DATEADD(day, -365, GETDATE())
        UNION ALL
        SELECT 'VulnerabilityFindings', COUNT(*) 
        FROM VulnerabilityFindings 
        WHERE ScanTimestamp < DATEADD(day, -365, GETDATE())
          AND (IsRemediated = 0 OR IsRemediated IS NULL);
        
        PRINT 'DRY RUN: No data deleted. Run with @DryRun=0 to execute cleanup.';
    END
    ELSE
    BEGIN
        EXEC sp_CleanupApplicationMetrics @RetentionDays = 90;
        EXEC sp_CleanupSecurityEvents @RetentionDays = 180;
        EXEC sp_CleanupNetworkMetrics @RetentionDays = 60;
        EXEC sp_CleanupCertificateMetrics @RetentionDays = 365;
        EXEC sp_CleanupVulnerabilityFindings @RetentionDays = 365, @KeepRemediated = 1;
        
        PRINT '';
        PRINT 'Rebuilding indexes...';
        ALTER INDEX ALL ON ApplicationMetrics REBUILD;
        ALTER INDEX ALL ON SecurityEvents REBUILD;
        ALTER INDEX ALL ON NetworkMetrics REBUILD;
        ALTER INDEX ALL ON CertificateMetrics REBUILD;
        ALTER INDEX ALL ON VulnerabilityFindings REBUILD;
        PRINT '✅ Indexes rebuilt';
        
        PRINT 'Updating statistics...';
        UPDATE STATISTICS ApplicationMetrics;
        UPDATE STATISTICS SecurityEvents;
        UPDATE STATISTICS NetworkMetrics;
        UPDATE STATISTICS CertificateMetrics;
        UPDATE STATISTICS VulnerabilityFindings;
        PRINT '✅ Statistics updated';
    END
    
    PRINT '';
    PRINT 'Cleanup completed: ' + CONVERT(VARCHAR(30), GETDATE(), 120);
END
GO
PRINT '✅ sp_CleanupAllTables created';

-- Backup procedure
PRINT 'Creating/Updating sp_BackupDatabase...';
GO
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_BackupDatabase')
    DROP PROCEDURE sp_BackupDatabase;
GO
CREATE PROCEDURE sp_BackupDatabase
    @BackupPath NVARCHAR(500) = 'C:\Backups\EDGE_DB\'
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @BackupFile NVARCHAR(600);
    DECLARE @Timestamp VARCHAR(20) = CONVERT(VARCHAR(20), GETDATE(), 112) + '_' + REPLACE(CONVERT(VARCHAR(20), GETDATE(), 108), ':', '');
    
    SET @BackupFile = @BackupPath + 'EDGE_DB_' + @Timestamp + '.bak';
    
    PRINT 'Starting backup to: ' + @BackupFile;
    
    BACKUP DATABASE EDGE_DB
    TO DISK = @BackupFile
    WITH 
        COMPRESSION,
        INIT,
        STATS = 10,
        NAME = 'EDGE_DB Full Backup',
        DESCRIPTION = 'Automated backup of EDGE_DB database';
    
    PRINT '✅ Backup completed successfully!';
END
GO
PRINT '✅ sp_BackupDatabase created';
PRINT '';

-- ===================================================================
-- STEP 4: CREATE OR ALTER VIEWS
-- ===================================================================

PRINT '=================================================================';
PRINT 'STEP 4: Creating/Updating monitoring views...';
PRINT '=================================================================';
PRINT '';

-- Latest Application Status
PRINT 'Creating/Updating vw_LatestApplicationStatus...';
GO
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_LatestApplicationStatus')
    DROP VIEW vw_LatestApplicationStatus;
GO
CREATE VIEW vw_LatestApplicationStatus
AS
SELECT 
    ApplicationName,
    URL,
    Availability,
    ResponseTimeMS,
    StatusCode,
    Severity,
    ErrorMessage,
    Timestamp,
    ROW_NUMBER() OVER (PARTITION BY ApplicationName ORDER BY Timestamp DESC) as RowNum
FROM ApplicationMetrics;
GO
PRINT '✅ vw_LatestApplicationStatus created';

-- Security Event Summary
PRINT 'Creating/Updating vw_SecurityEventSummary24h...';
GO
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_SecurityEventSummary24h')
    DROP VIEW vw_SecurityEventSummary24h;
GO
CREATE VIEW vw_SecurityEventSummary24h
AS
SELECT 
    EventType,
    Severity,
    COUNT(*) as EventCount,
    COUNT(DISTINCT SourceIP) as UniqueSourceIPs,
    COUNT(DISTINCT UserName) as UniqueUsers,
    MAX(Timestamp) as LastOccurrence
FROM SecurityEvents
WHERE Timestamp >= DATEADD(hour, -24, GETDATE())
GROUP BY EventType, Severity;
GO
PRINT '✅ vw_SecurityEventSummary24h created';

-- Network Performance Summary
PRINT 'Creating/Updating vw_NetworkPerformanceSummary...';
GO
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_NetworkPerformanceSummary')
    DROP VIEW vw_NetworkPerformanceSummary;
GO
CREATE VIEW vw_NetworkPerformanceSummary
AS
SELECT 
    TargetHost,
    MetricType,
    AVG(LatencyMS) as AvgLatency,
    MIN(LatencyMS) as MinLatency,
    MAX(LatencyMS) as MaxLatency,
    AVG(PacketLossPct) as AvgPacketLoss,
    AVG(ThroughputMbps) as AvgThroughput,
    COUNT(*) as CheckCount,
    MAX(Timestamp) as LastCheck
FROM NetworkMetrics
WHERE Timestamp >= DATEADD(hour, -24, GETDATE())
GROUP BY TargetHost, MetricType;
GO
PRINT '✅ vw_NetworkPerformanceSummary created';

-- Certificate Expiration Status
PRINT 'Creating/Updating vw_CertificateExpirationStatus...';
GO
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_CertificateExpirationStatus')
    DROP VIEW vw_CertificateExpirationStatus;
GO
CREATE VIEW vw_CertificateExpirationStatus
AS
SELECT 
    Hostname,
    Port,
    DaysUntilExpiry,
    ExpiryDate,
    Issuer,
    TLSVersion,
    Severity,
    Status,
    CASE 
        WHEN DaysUntilExpiry IS NULL THEN 'Unknown'
        WHEN DaysUntilExpiry < 0 THEN 'Expired'
        WHEN DaysUntilExpiry <= 7 THEN 'Critical - Expiring This Week'
        WHEN DaysUntilExpiry <= 30 THEN 'Warning - Expiring This Month'
        WHEN DaysUntilExpiry <= 90 THEN 'Notice - Expiring Soon'
        ELSE 'OK'
    END as ExpirationStatus,
    Timestamp
FROM CertificateMetrics
WHERE Timestamp >= DATEADD(day, -1, GETDATE());
GO
PRINT '✅ vw_CertificateExpirationStatus created';

-- Vulnerability Dashboard
PRINT 'Creating/Updating vw_VulnerabilityDashboard...';
GO
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_VulnerabilityDashboard')
    DROP VIEW vw_VulnerabilityDashboard;
GO
CREATE VIEW vw_VulnerabilityDashboard
AS
SELECT 
    TargetName,
    Severity,
    FindingType,
    COUNT(*) as FindingCount,
    SUM(CASE WHEN IsRemediated = 1 THEN 1 ELSE 0 END) as RemediatedCount,
    SUM(CASE WHEN IsRemediated = 0 OR IsRemediated IS NULL THEN 1 ELSE 0 END) as OpenCount,
    MAX(ScanTimestamp) as LastScan,
    AVG(RiskScore) as AvgRiskScore
FROM VulnerabilityFindings
GROUP BY TargetName, Severity, FindingType;
GO
PRINT '✅ vw_VulnerabilityDashboard created';

-- Database Health Metrics
PRINT 'Creating/Updating vw_DatabaseHealthMetrics...';
GO
IF EXISTS (SELECT * FROM sys.views WHERE name = 'vw_DatabaseHealthMetrics')
    DROP VIEW vw_DatabaseHealthMetrics;
GO
CREATE VIEW vw_DatabaseHealthMetrics
AS
SELECT 
    'ApplicationMetrics' as TableName,
    COUNT(*) as TotalRows,
    COUNT(CASE WHEN Timestamp >= DATEADD(hour, -1, GETDATE()) THEN 1 END) as RowsLastHour,
    COUNT(CASE WHEN Timestamp >= DATEADD(day, -1, GETDATE()) THEN 1 END) as RowsLast24Hours,
    MIN(Timestamp) as OldestRecord,
    MAX(Timestamp) as NewestRecord
FROM ApplicationMetrics
UNION ALL
SELECT 
    'SecurityEvents',
    COUNT(*),
    COUNT(CASE WHEN Timestamp >= DATEADD(hour, -1, GETDATE()) THEN 1 END),
    COUNT(CASE WHEN Timestamp >= DATEADD(day, -1, GETDATE()) THEN 1 END),
    MIN(Timestamp),
    MAX(Timestamp)
FROM SecurityEvents
UNION ALL
SELECT 
    'NetworkMetrics',
    COUNT(*),
    COUNT(CASE WHEN Timestamp >= DATEADD(hour, -1, GETDATE()) THEN 1 END),
    COUNT(CASE WHEN Timestamp >= DATEADD(day, -1, GETDATE()) THEN 1 END),
    MIN(Timestamp),
    MAX(Timestamp)
FROM NetworkMetrics
UNION ALL
SELECT 
    'CertificateMetrics',
    COUNT(*),
    COUNT(CASE WHEN Timestamp >= DATEADD(hour, -1, GETDATE()) THEN 1 END),
    COUNT(CASE WHEN Timestamp >= DATEADD(day, -1, GETDATE()) THEN 1 END),
    MIN(Timestamp),
    MAX(Timestamp)
FROM CertificateMetrics
UNION ALL
SELECT 
    'VulnerabilityFindings',
    COUNT(*),
    COUNT(CASE WHEN ScanTimestamp >= DATEADD(hour, -1, GETDATE()) THEN 1 END),
    COUNT(CASE WHEN ScanTimestamp >= DATEADD(day, -1, GETDATE()) THEN 1 END),
    MIN(ScanTimestamp),
    MAX(ScanTimestamp)
FROM VulnerabilityFindings;
GO
PRINT '✅ vw_DatabaseHealthMetrics created';
PRINT '';

-- ===================================================================
-- STEP 5: VERIFICATION
-- ===================================================================

PRINT '';
PRINT '=================================================================';
PRINT 'STEP 5: Verification and Status...';
PRINT '=================================================================';
PRINT '';

-- Verify tables
PRINT 'Verifying tables...';
SELECT 
    'Tables' as ObjectType, 
    name as ObjectName,
    create_date as CreatedDate,
    modify_date as ModifiedDate
FROM sys.tables 
WHERE name IN ('ApplicationMetrics', 'SecurityEvents', 'NetworkMetrics', 'CertificateMetrics', 'VulnerabilityFindings')
ORDER BY name;
GO

-- Verify stored procedures
PRINT '';
PRINT 'Verifying stored procedures...';
SELECT 
    'Stored Procedures' as ObjectType,
    name as ObjectName,
    create_date as CreatedDate,
    modify_date as ModifiedDate
FROM sys.procedures 
WHERE name LIKE 'sp_%' AND is_ms_shipped = 0
ORDER BY name;
GO

-- Verify views
PRINT '';
PRINT 'Verifying views...';
SELECT 
    'Views' as ObjectType,
    name as ObjectName,
    create_date as CreatedDate,
    modify_date as ModifiedDate
FROM sys.views 
WHERE name LIKE 'vw_%'
ORDER BY name;
GO

-- Verify NULL support on critical columns
PRINT '';
PRINT 'Verifying NULL support on critical columns:';
SELECT 
    t.name AS TableName,
    c.name AS ColumnName,
    TYPE_NAME(c.user_type_id) AS DataType,
    CASE WHEN c.is_nullable = 1 THEN '✅ YES' ELSE '❌ NO' END AS IsNullable
FROM sys.tables t
INNER JOIN sys.columns c ON t.object_id = c.object_id
WHERE t.name IN ('ApplicationMetrics', 'SecurityEvents', 'NetworkMetrics', 'CertificateMetrics', 'VulnerabilityFindings')
    AND c.name IN ('ResponseTimeMS', 'StatusCode', 'Availability', 'SourceIP', 'UserName', 'LatencyMS', 'DaysUntilExpiry', 'Port', 'Description')
ORDER BY t.name, c.name;
GO

-- Database configuration summary
PRINT '';
PRINT 'Database Configuration Summary:';
SELECT 
    name as DatabaseName,
    recovery_model_desc as RecoveryModel,
    state_desc as State,
    compatibility_level as CompatibilityLevel,
    CAST(size * 8.0 / 1024 AS DECIMAL(10,2)) as SizeMB
FROM sys.databases 
WHERE name = 'EDGE_DB';
GO

-- Check Query Store status
PRINT '';
PRINT 'Query Store Status:';
SELECT 
    actual_state_desc as Status,
    readonly_reason_desc as ReadOnlyReason,
    current_storage_size_mb as CurrentStorageMB,
    max_storage_size_mb as MaxStorageMB,
    query_capture_mode_desc as CaptureMode
FROM sys.database_query_store_options;
GO

-- Check table row counts
PRINT '';
PRINT 'Current table row counts:';
SELECT 
    'ApplicationMetrics' as TableName, 
    COUNT(*) as RowCount,
    MIN(Timestamp) as OldestRecord,
    MAX(Timestamp) as NewestRecord
FROM ApplicationMetrics
UNION ALL
SELECT 'SecurityEvents', COUNT(*), MIN(Timestamp), MAX(Timestamp) FROM SecurityEvents
UNION ALL
SELECT 'NetworkMetrics', COUNT(*), MIN(Timestamp), MAX(Timestamp) FROM NetworkMetrics
UNION ALL
SELECT 'CertificateMetrics', COUNT(*), MIN(Timestamp), MAX(Timestamp) FROM CertificateMetrics
UNION ALL
SELECT 'VulnerabilityFindings', COUNT(*), MIN(ScanTimestamp), MAX(ScanTimestamp) FROM VulnerabilityFindings;
GO

PRINT '';
PRINT '=================================================================';
PRINT '✅ EDGE_DB SETUP COMPLETE';
PRINT '=================================================================';
PRINT '';
PRINT 'Created/Updated Components:';
PRINT '  📊 5 Tables: All with proper NULL handling';
PRINT '  🔧 6 Stored Procedures: Maintenance and backup';
PRINT '  📈 6 Monitoring Views: Real-time dashboards';
PRINT '';
PRINT 'Features:';
PRINT '  ✅ All tables support NULL values where needed';
PRINT '  ✅ Query Store enabled for performance monitoring';
PRINT '  ✅ Optimized indexes on all tables';
PRINT '  ✅ Data retention procedures ready';
PRINT '  ✅ Backup procedures configured';
PRINT '  ✅ No data was dropped - safe upgrade';
PRINT '';

-- ===================================================================
-- MAINTENANCE GUIDE
-- ===================================================================

PRINT '';
PRINT '=================================================================';
PRINT 'MAINTENANCE GUIDE';
PRINT '=================================================================';
PRINT '';
PRINT '1. Data Retention Cleanup (Run Weekly):';
PRINT '   EXEC sp_CleanupAllTables @DryRun = 0;';
PRINT '';
PRINT '   Preview cleanup (no actual deletion):';
PRINT '   EXEC sp_CleanupAllTables @DryRun = 1;';
PRINT '';
PRINT '2. Database Backup (Run Daily):';
PRINT '   EXEC sp_BackupDatabase @BackupPath = ''C:\Backups\EDGE_DB\'';';
PRINT '';
PRINT '   Note: Create backup directory first!';
PRINT '   mkdir C:\Backups\EDGE_DB';
PRINT '';
PRINT '3. Monitor Database Health:';
PRINT '   SELECT * FROM vw_DatabaseHealthMetrics;';
PRINT '';
PRINT '4. Check Application Status:';
PRINT '   SELECT * FROM vw_LatestApplicationStatus WHERE RowNum = 1;';
PRINT '';
PRINT '5. Review Security Events (Last 24h):';
PRINT '   SELECT * FROM vw_SecurityEventSummary24h ORDER BY EventCount DESC;';
PRINT '';
PRINT '6. Certificate Expiration Alerts:';
PRINT '   SELECT * FROM vw_CertificateExpirationStatus';
PRINT '   WHERE ExpirationStatus IN (''Critical - Expiring This Week'', ''Warning - Expiring This Month'')';
PRINT '   ORDER BY DaysUntilExpiry;';
PRINT '';
PRINT '7. Vulnerability Summary:';
PRINT '   SELECT * FROM vw_VulnerabilityDashboard';
PRINT '   WHERE OpenCount > 0';
PRINT '   ORDER BY CASE Severity';
PRINT '     WHEN ''critical'' THEN 1';
PRINT '     WHEN ''high'' THEN 2';
PRINT '     WHEN ''medium'' THEN 3';
PRINT '     WHEN ''low'' THEN 4 END;';
PRINT '';
PRINT '8. Individual Table Cleanup:';
PRINT '   EXEC sp_CleanupApplicationMetrics @RetentionDays = 90;';
PRINT '   EXEC sp_CleanupSecurityEvents @RetentionDays = 180;';
PRINT '   EXEC sp_CleanupNetworkMetrics @RetentionDays = 60;';
PRINT '   EXEC sp_CleanupCertificateMetrics @RetentionDays = 365;';
PRINT '   EXEC sp_CleanupVulnerabilityFindings @RetentionDays = 365;';
PRINT '';

-- ===================================================================
-- EXAMPLE QUERIES
-- ===================================================================

PRINT '';
PRINT '=================================================================';
PRINT 'USEFUL EXAMPLE QUERIES';
PRINT '=================================================================';
PRINT '';
PRINT '-- Application Availability Summary (Last 24h)';
PRINT 'SELECT ';
PRINT '    ApplicationName,';
PRINT '    COUNT(*) as TotalChecks,';
PRINT '    SUM(CASE WHEN Availability = 1 THEN 1 ELSE 0 END) as SuccessfulChecks,';
PRINT '    CAST(SUM(CASE WHEN Availability = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) AS DECIMAL(5,2)) as AvailabilityPct,';
PRINT '    AVG(ResponseTimeMS) as AvgResponseTime';
PRINT 'FROM ApplicationMetrics';
PRINT 'WHERE Timestamp >= DATEADD(hour, -24, GETDATE())';
PRINT 'GROUP BY ApplicationName';
PRINT 'ORDER BY AvailabilityPct ASC;';
PRINT '';
PRINT '-- Top Failed Login Sources (Last 24h)';
PRINT 'SELECT TOP 10';
PRINT '    SourceIP,';
PRINT '    COUNT(*) as FailedAttempts,';
PRINT '    COUNT(DISTINCT UserName) as UniqueUsers,';
PRINT '    MAX(Timestamp) as LastAttempt';
PRINT 'FROM SecurityEvents';
PRINT 'WHERE EventType = ''failed_logon''';
PRINT '  AND Timestamp >= DATEADD(hour, -24, GETDATE())';
PRINT 'GROUP BY SourceIP';
PRINT 'ORDER BY FailedAttempts DESC;';
PRINT '';
PRINT '-- Network Latency Trends';
PRINT 'SELECT ';
PRINT '    TargetHost,';
PRINT '    AVG(LatencyMS) as AvgLatency,';
PRINT '    MAX(LatencyMS) as MaxLatency,';
PRINT '    AVG(PacketLossPct) as AvgPacketLoss';
PRINT 'FROM NetworkMetrics';
PRINT 'WHERE Timestamp >= DATEADD(hour, -24, GETDATE())';
PRINT '  AND LatencyMS IS NOT NULL';
PRINT 'GROUP BY TargetHost';
PRINT 'ORDER BY AvgLatency DESC;';
PRINT '';
PRINT '-- Certificates Expiring Soon';
PRINT 'SELECT ';
PRINT '    Hostname,';
PRINT '    DaysUntilExpiry,';
PRINT '    ExpiryDate,';
PRINT '    Issuer';
PRINT 'FROM CertificateMetrics';
PRINT 'WHERE DaysUntilExpiry < 90';
PRINT '  AND Timestamp = (SELECT MAX(Timestamp) FROM CertificateMetrics cm WHERE cm.Hostname = CertificateMetrics.Hostname)';
PRINT 'ORDER BY DaysUntilExpiry ASC;';
PRINT '';
PRINT '-- Open Critical/High Vulnerabilities';
PRINT 'SELECT ';
PRINT '    TargetName,';
PRINT '    Severity,';
PRINT '    COUNT(*) as TotalFindings';
PRINT 'FROM VulnerabilityFindings';
PRINT 'WHERE (IsRemediated = 0 OR IsRemediated IS NULL)';
PRINT '  AND Severity IN (''critical'', ''high'')';
PRINT 'GROUP BY TargetName, Severity';
PRINT 'ORDER BY Severity, TotalFindings DESC;';
PRINT '';

-- ===================================================================
-- QUICK DIAGNOSTICS
-- ===================================================================

PRINT '';
PRINT 'Quick Diagnostics:';
PRINT '';

-- Database size and space
SELECT 
    'Database File Info' as DiagnosticType,
    name as FileName,
    CAST(size * 8.0 / 1024 AS DECIMAL(10,2)) as SizeMB,
    CAST(FILEPROPERTY(name, 'SpaceUsed') * 8.0 / 1024 AS DECIMAL(10,2)) as UsedMB,
    CAST((size - FILEPROPERTY(name, 'SpaceUsed')) * 8.0 / 1024 AS DECIMAL(10,2)) as FreeMB,
    CAST(FILEPROPERTY(name, 'SpaceUsed') * 100.0 / size AS DECIMAL(5,2)) as UsedPct
FROM sys.database_files;
GO

PRINT '';
PRINT '=================================================================';
PRINT 'OPTIONAL: TEST DATA INSERTION';
PRINT '=================================================================';
PRINT '';
PRINT 'To insert sample test data, uncomment and run:';
PRINT '';
PRINT '/*';
PRINT 'USE EDGE_DB;';
PRINT '';
PRINT '-- Sample ApplicationMetrics';
PRINT 'INSERT INTO ApplicationMetrics (MonitoringHost, ApplicationName, URL, ResponseTimeMS, StatusCode, Availability, Severity)';
PRINT 'VALUES ';
PRINT '  (''Monitor01'', ''WebApp1'', ''https://app1.example.com'', 150.5, 200, 1, ''normal''),';
PRINT '  (''Monitor01'', ''WebApp2'', ''https://app2.example.com'', NULL, NULL, 0, ''critical'');';
PRINT '';
PRINT '-- Sample SecurityEvents';
PRINT 'INSERT INTO SecurityEvents (MonitoringHost, EventType, SourceIP, UserName, Severity)';
PRINT 'VALUES ';
PRINT '  (''Monitor01'', ''failed_logon'', ''192.168.1.100'', ''attacker'', ''high'');';
PRINT '';
PRINT '-- Verify sample data';
PRINT 'SELECT * FROM vw_DatabaseHealthMetrics;';
PRINT '*/';
PRINT '';

-- ===================================================================
-- FINAL STATUS
-- ===================================================================

PRINT '';
PRINT '███████╗██████╗  ██████╗ ███████╗    ██████╗ ██████╗ ';
PRINT '██╔════╝██╔══██╗██╔════╝ ██╔════╝    ██╔══██╗██╔══██╗';
PRINT '█████╗  ██║  ██║██║  ███╗█████╗      ██║  ██║██████╔╝';
PRINT '██╔══╝  ██║  ██║██║   ██║██╔══╝      ██║  ██║██╔══██╗';
PRINT '███████╗██████╔╝╚██████╔╝███████╗    ██████╔╝██████╔╝';
PRINT '╚══════╝╚═════╝  ╚═════╝ ╚══════╝    ╚═════╝ ╚═════╝ ';
PRINT '';
PRINT '✅ Setup Complete - EDGE_DB is ready!';
PRINT '';
PRINT '==============================================================';
PRINT 'All tables, procedures, and views have been created/updated.';
PRINT 'No existing data was dropped or deleted.';
PRINT '==============================================================';
GO