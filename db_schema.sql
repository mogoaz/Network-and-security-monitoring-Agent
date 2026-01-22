-- ===================================================================
--          SECURITY & NETWORK MONITORING DATABASE SCHEMA
-- ===================================================================
-- Database: MonitoringDB
-- Purpose: Store all security and network metrics from the agent
-- ===================================================================

USE master;
GO

-- Create database if it doesn't exist
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'MonitoringDB')
BEGIN
    CREATE DATABASE MonitoringDB;
    PRINT 'Database MonitoringDB created successfully';
END
ELSE
BEGIN
    PRINT 'Database MonitoringDB already exists';
END
GO

USE MonitoringDB;
GO

-- ===================================================================
--                  TABLE 1: SECURITY METRICS
-- ===================================================================
IF OBJECT_ID('dbo.SecurityMetrics', 'U') IS NOT NULL
    DROP TABLE dbo.SecurityMetrics;
GO

CREATE TABLE dbo.SecurityMetrics (
    -- Primary Key
    MetricID BIGINT IDENTITY(1,1) PRIMARY KEY,
    
    -- Timestamp Information
    CollectionTime DATETIME2(3) NOT NULL DEFAULT GETDATE(),
    EventTime DATETIME2(3) NOT NULL,
    
    -- Source Information
    MonitoringHost NVARCHAR(255) NOT NULL,
    MonitoringHostIP NVARCHAR(50) NULL,
    RemoteServer NVARCHAR(255) NULL,
    RemoteServerHost NVARCHAR(255) NULL,
    
    -- Metric Information
    MetricKey NVARCHAR(500) NOT NULL,
    MetricValue DECIMAL(18,4) NOT NULL,
    MetricUnit NVARCHAR(50) NULL,
    
    -- Event Classification
    EventType NVARCHAR(100) NULL,
    EventID INT NULL,
    EventSubtype NVARCHAR(100) NULL,
    SecurityCategory NVARCHAR(100) NULL,
    
    -- Security Event Details
    TargetUserName NVARCHAR(255) NULL,
    TargetDomainName NVARCHAR(255) NULL,
    SourceNetworkAddress NVARCHAR(50) NULL,
    SourcePort NVARCHAR(10) NULL,
    WorkstationName NVARCHAR(255) NULL,
    
    -- Authentication Details
    LogonType NVARCHAR(50) NULL,
    LogonTypeDescription NVARCHAR(100) NULL,
    LogonProcessName NVARCHAR(255) NULL,
    AuthenticationPackage NVARCHAR(255) NULL,
    FailureReason NVARCHAR(500) NULL,
    
    -- Threat Analysis
    ThreatScore INT NULL,
    SeverityLevel NVARCHAR(50) NULL,
    ThreatCategory NVARCHAR(100) NULL,
    ThreatName NVARCHAR(500) NULL,
    ThreatAction NVARCHAR(100) NULL,
    
    -- Firewall Specific
    FirewallDirection NVARCHAR(50) NULL,
    Protocol NVARCHAR(50) NULL,
    DestinationAddress NVARCHAR(50) NULL,
    DestinationPort NVARCHAR(10) NULL,
    ApplicationPath NVARCHAR(1000) NULL,
    ProcessId NVARCHAR(50) NULL,
    
    -- MFA Details
    MFAContext NVARCHAR(100) NULL,
    MFASuccess BIT NULL,
    MFAType NVARCHAR(100) NULL,
    
    -- Vulnerability Details
    VulnerabilityCategory NVARCHAR(100) NULL,
    VulnerabilitySeverity NVARCHAR(50) NULL,
    VulnerabilityTitle NVARCHAR(500) NULL,
    CVEID NVARCHAR(50) NULL,
    
    -- Endpoint Threat Details
    EndpointThreatSeverity NVARCHAR(50) NULL,
    EndpointThreatCategory NVARCHAR(100) NULL,
    FilePath NVARCHAR(1000) NULL,
    DetectionUser NVARCHAR(255) NULL,
    
    -- Audit Trail Details
    AuditTrailStatus NVARCHAR(100) NULL,
    AuditHealthScore DECIMAL(5,2) NULL,
    
    -- Analysis Results
    Alerts NVARCHAR(MAX) NULL,
    Recommendation NVARCHAR(MAX) NULL,
    AnalysisMetadata NVARCHAR(MAX) NULL,
    
    -- Dimensional Attributes
    Dimensions NVARCHAR(MAX) NULL,
    
    -- Raw Data
    RawMessage NVARCHAR(MAX) NULL,
    CollectionMethod NVARCHAR(100) NULL,
    
    -- Indexing and Partitioning
    CONSTRAINT CK_MetricValue CHECK (MetricValue >= -999999999 AND MetricValue <= 999999999),
    INDEX IX_CollectionTime NONCLUSTERED (CollectionTime DESC),
    INDEX IX_EventTime NONCLUSTERED (EventTime DESC),
    INDEX IX_MonitoringHost NONCLUSTERED (MonitoringHost),
    INDEX IX_MetricKey NONCLUSTERED (MetricKey),
    INDEX IX_EventType NONCLUSTERED (EventType),
    INDEX IX_SourceIP NONCLUSTERED (SourceNetworkAddress),
    INDEX IX_TargetUser NONCLUSTERED (TargetUserName),
    INDEX IX_ThreatScore NONCLUSTERED (ThreatScore) WHERE ThreatScore IS NOT NULL,
    INDEX IX_SeverityLevel NONCLUSTERED (SeverityLevel) WHERE SeverityLevel IS NOT NULL
);
GO

-- Add extended properties for documentation
EXEC sp_addextendedproperty 
    @name = N'MS_Description', 
    @value = N'Stores all security-related metrics including failed logons, firewall events, threats, MFA, vulnerabilities, and audit trails',
    @level0type = N'SCHEMA', @level0name = 'dbo',
    @level1type = N'TABLE', @level1name = 'SecurityMetrics';
GO

-- ===================================================================
--                  TABLE 2: NETWORK METRICS
-- ===================================================================
IF OBJECT_ID('dbo.NetworkMetrics', 'U') IS NOT NULL
    DROP TABLE dbo.NetworkMetrics;
GO

CREATE TABLE dbo.NetworkMetrics (
    -- Primary Key
    MetricID BIGINT IDENTITY(1,1) PRIMARY KEY,
    
    -- Timestamp Information
    CollectionTime DATETIME2(3) NOT NULL DEFAULT GETDATE(),
    MeasurementTime DATETIME2(3) NOT NULL,
    
    -- Source Information
    MonitoringHost NVARCHAR(255) NOT NULL,
    MonitoringHostIP NVARCHAR(50) NULL,
    
    -- Metric Information
    MetricKey NVARCHAR(500) NOT NULL,
    MetricValue DECIMAL(18,4) NOT NULL,
    MetricUnit NVARCHAR(50) NULL,
    
    -- Network Target Information
    TargetHost NVARCHAR(255) NULL,
    TargetName NVARCHAR(255) NULL,
    TargetIP NVARCHAR(50) NULL,
    TargetPort INT NULL,
    
    -- Metric Category
    MetricCategory NVARCHAR(100) NULL, -- ICMP, TLS, Bandwidth, Connection, Interface, DNS, WAN
    MetricType NVARCHAR(100) NULL,     -- Latency, PacketLoss, Throughput, etc.
    
    -- ICMP/Ping Metrics
    PingLatency DECIMAL(10,3) NULL,
    PacketLoss DECIMAL(5,2) NULL,
    Jitter DECIMAL(10,3) NULL,
    Availability BIT NULL,
    
    -- TLS/SSL Metrics
    SSLHandshakeTime DECIMAL(10,3) NULL,
    CertificateExpiryDays INT NULL,
    CertificateIssuer NVARCHAR(500) NULL,
    CertificateSubject NVARCHAR(500) NULL,
    TLSSuccess BIT NULL,
    
    -- DNS Metrics
    DNSResolutionTime DECIMAL(10,3) NULL,
    DNSServer NVARCHAR(50) NULL,
    TestDomain NVARCHAR(255) NULL,
    
    -- Bandwidth Metrics
    DownloadSpeed DECIMAL(18,4) NULL, -- Bytes per second
    UploadSpeed DECIMAL(18,4) NULL,   -- Bytes per second
    DownloadMbps DECIMAL(10,2) NULL,
    UploadMbps DECIMAL(10,2) NULL,
    PacketsReceived BIGINT NULL,
    PacketsSent BIGINT NULL,
    ErrorsReceived BIGINT NULL,
    ErrorsSent BIGINT NULL,
    DropsReceived BIGINT NULL,
    DropsSent BIGINT NULL,
    
    -- Interface Metrics
    InterfaceName NVARCHAR(255) NULL,
    InterfaceStatus NVARCHAR(50) NULL,
    InterfaceSpeed BIGINT NULL,
    InterfaceMTU INT NULL,
    IPv4Addresses INT NULL,
    IPv6Addresses INT NULL,
    
    -- Connection Metrics
    ConnectionStatus NVARCHAR(100) NULL,
    ConnectionType NVARCHAR(100) NULL,
    TotalConnections INT NULL,
    UniqueRemoteHosts INT NULL,
    UniqueLocalPorts INT NULL,
    
    -- Process Network Metrics
    ProcessName NVARCHAR(255) NULL,
    ProcessID INT NULL,
    ProcessConnectionCount INT NULL,
    
    -- WAN Link Metrics
    WANLinkType NVARCHAR(100) NULL,
    WANAvailability DECIMAL(5,2) NULL,
    WANLatency DECIMAL(10,3) NULL,
    WANPacketLoss DECIMAL(5,2) NULL,
    WANStatus NVARCHAR(50) NULL,
    WANHealthScore DECIMAL(5,2) NULL,
    
    -- HTTP Endpoint Metrics
    HTTPStatusCode INT NULL,
    HTTPResponseTime DECIMAL(10,3) NULL,
    HTTPThroughput DECIMAL(18,4) NULL,
    HTTPContentSize DECIMAL(18,4) NULL,
    
    -- Performance Indicators
    PerformanceScore DECIMAL(5,2) NULL,
    HealthStatus NVARCHAR(50) NULL,
    
    -- Dimensional Attributes
    Dimensions NVARCHAR(MAX) NULL,
    
    -- Collection Details
    CollectionMethod NVARCHAR(100) NULL,
    SampleCount INT NULL,
    
    -- Indexing and Partitioning
    CONSTRAINT CK_NetworkMetricValue CHECK (MetricValue >= -999999999 AND MetricValue <= 999999999),
    INDEX IX_CollectionTime NONCLUSTERED (CollectionTime DESC),
    INDEX IX_MeasurementTime NONCLUSTERED (MeasurementTime DESC),
    INDEX IX_MonitoringHost NONCLUSTERED (MonitoringHost),
    INDEX IX_MetricKey NONCLUSTERED (MetricKey),
    INDEX IX_MetricCategory NONCLUSTERED (MetricCategory),
    INDEX IX_TargetHost NONCLUSTERED (TargetHost),
    INDEX IX_InterfaceName NONCLUSTERED (InterfaceName) WHERE InterfaceName IS NOT NULL,
    INDEX IX_ProcessName NONCLUSTERED (ProcessName) WHERE ProcessName IS NOT NULL
);
GO

-- Add extended properties for documentation
EXEC sp_addextendedproperty 
    @name = N'MS_Description', 
    @value = N'Stores all network-related metrics including ICMP, TLS, bandwidth, connections, interfaces, DNS, and WAN links',
    @level0type = N'SCHEMA', @level0name = 'dbo',
    @level1type = N'TABLE', @level1name = 'NetworkMetrics';
GO

-- ===================================================================
--                  SUPPORTING VIEWS FOR ANALYSIS
-- ===================================================================

-- View: Recent Security Threats
CREATE OR ALTER VIEW dbo.vw_RecentSecurityThreats
AS
SELECT TOP 1000
    MetricID,
    CollectionTime,
    EventTime,
    MonitoringHost,
    EventType,
    TargetUserName,
    SourceNetworkAddress,
    ThreatScore,
    SeverityLevel,
    ThreatCategory,
    ThreatName,
    Alerts,
    Recommendation
FROM dbo.SecurityMetrics
WHERE ThreatScore IS NOT NULL AND ThreatScore > 0
ORDER BY CollectionTime DESC, ThreatScore DESC;
GO

-- View: Network Performance Summary
CREATE OR ALTER VIEW dbo.vw_NetworkPerformanceSummary
AS
SELECT TOP 1000
    MetricID,
    CollectionTime,
    MeasurementTime,
    MonitoringHost,
    MetricCategory,
    TargetHost,
    TargetName,
    PingLatency,
    PacketLoss,
    Availability,
    SSLHandshakeTime,
    DownloadMbps,
    UploadMbps,
    HealthStatus
FROM dbo.NetworkMetrics
WHERE MetricCategory IN ('ICMP', 'TLS', 'Bandwidth', 'WAN')
ORDER BY CollectionTime DESC;
GO

-- View: Failed Logon Analysis
CREATE OR ALTER VIEW dbo.vw_FailedLogonAnalysis
AS
SELECT TOP 1000
    MetricID,
    CollectionTime,
    EventTime,
    MonitoringHost,
    TargetUserName,
    TargetDomainName,
    SourceNetworkAddress,
    LogonType,
    LogonTypeDescription,
    FailureReason,
    ThreatScore,
    SeverityLevel,
    Alerts
FROM dbo.SecurityMetrics
WHERE EventType = 'FailedLogon'
ORDER BY CollectionTime DESC, ThreatScore DESC;
GO

-- View: Firewall Activity Summary
CREATE OR ALTER VIEW dbo.vw_FirewallActivitySummary
AS
SELECT TOP 1000
    MetricID,
    CollectionTime,
    EventTime,
    MonitoringHost,
    EventType,
    SourceNetworkAddress,
    DestinationAddress,
    DestinationPort,
    Protocol,
    FirewallDirection,
    ApplicationPath,
    SeverityLevel
FROM dbo.SecurityMetrics
WHERE EventType IN ('FirewallDropped', 'FirewallViolation', 'FirewallPermitted', 'FirewallAllowed')
ORDER BY CollectionTime DESC;
GO

-- View: Endpoint Threat Detection
CREATE OR ALTER VIEW dbo.vw_EndpointThreatDetection
AS
SELECT TOP 1000
    MetricID,
    CollectionTime,
    EventTime,
    MonitoringHost,
    EventType,
    ThreatName,
    EndpointThreatSeverity,
    EndpointThreatCategory,
    FilePath,
    DetectionUser,
    ThreatAction,
    Recommendation
FROM dbo.SecurityMetrics
WHERE EventType IN ('ThreatDetected', 'ThreatRemediated', 'SuspiciousActivity')
ORDER BY CollectionTime DESC;
GO

-- View: Bandwidth Usage Trends
CREATE OR ALTER VIEW dbo.vw_BandwidthUsageTrends
AS
SELECT TOP 1000
    MetricID,
    CollectionTime,
    MeasurementTime,
    MonitoringHost,
    InterfaceName,
    DownloadMbps,
    UploadMbps,
    PacketsReceived,
    PacketsSent,
    ErrorsReceived + ErrorsSent AS TotalErrors,
    DropsReceived + DropsSent AS TotalDrops
FROM dbo.NetworkMetrics
WHERE MetricCategory = 'Bandwidth'
ORDER BY CollectionTime DESC;
GO

-- ===================================================================
--                  STORED PROCEDURES
-- ===================================================================

-- Procedure: Insert Security Metric (Bulk)
CREATE OR ALTER PROCEDURE dbo.usp_InsertSecurityMetricsBulk
    @MetricsJSON NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        BEGIN TRANSACTION;
        
        INSERT INTO dbo.SecurityMetrics (
            CollectionTime, EventTime, MonitoringHost, MonitoringHostIP,
            RemoteServer, RemoteServerHost, MetricKey, MetricValue, MetricUnit,
            EventType, EventID, EventSubtype, SecurityCategory,
            TargetUserName, TargetDomainName, SourceNetworkAddress, SourcePort, WorkstationName,
            LogonType, LogonTypeDescription, LogonProcessName, AuthenticationPackage, FailureReason,
            ThreatScore, SeverityLevel, ThreatCategory, ThreatName, ThreatAction,
            FirewallDirection, Protocol, DestinationAddress, DestinationPort, ApplicationPath, ProcessId,
            MFAContext, MFASuccess, MFAType,
            VulnerabilityCategory, VulnerabilitySeverity, VulnerabilityTitle, CVEID,
            EndpointThreatSeverity, EndpointThreatCategory, FilePath, DetectionUser,
            AuditTrailStatus, AuditHealthScore,
            Alerts, Recommendation, AnalysisMetadata, Dimensions, RawMessage, CollectionMethod
        )
        SELECT 
            ISNULL(CollectionTime, GETDATE()),
            ISNULL(EventTime, GETDATE()),
            MonitoringHost,
            MonitoringHostIP,
            RemoteServer,
            RemoteServerHost,
            MetricKey,
            MetricValue,
            MetricUnit,
            EventType,
            EventID,
            EventSubtype,
            SecurityCategory,
            TargetUserName,
            TargetDomainName,
            SourceNetworkAddress,
            SourcePort,
            WorkstationName,
            LogonType,
            LogonTypeDescription,
            LogonProcessName,
            AuthenticationPackage,
            FailureReason,
            ThreatScore,
            SeverityLevel,
            ThreatCategory,
            ThreatName,
            ThreatAction,
            FirewallDirection,
            Protocol,
            DestinationAddress,
            DestinationPort,
            ApplicationPath,
            ProcessId,
            MFAContext,
            MFASuccess,
            MFAType,
            VulnerabilityCategory,
            VulnerabilitySeverity,
            VulnerabilityTitle,
            CVEID,
            EndpointThreatSeverity,
            EndpointThreatCategory,
            FilePath,
            DetectionUser,
            AuditTrailStatus,
            AuditHealthScore,
            Alerts,
            Recommendation,
            AnalysisMetadata,
            Dimensions,
            RawMessage,
            CollectionMethod
        FROM OPENJSON(@MetricsJSON)
        WITH (
            CollectionTime DATETIME2,
            EventTime DATETIME2,
            MonitoringHost NVARCHAR(255),
            MonitoringHostIP NVARCHAR(50),
            RemoteServer NVARCHAR(255),
            RemoteServerHost NVARCHAR(255),
            MetricKey NVARCHAR(500),
            MetricValue DECIMAL(18,4),
            MetricUnit NVARCHAR(50),
            EventType NVARCHAR(100),
            EventID INT,
            EventSubtype NVARCHAR(100),
            SecurityCategory NVARCHAR(100),
            TargetUserName NVARCHAR(255),
            TargetDomainName NVARCHAR(255),
            SourceNetworkAddress NVARCHAR(50),
            SourcePort NVARCHAR(10),
            WorkstationName NVARCHAR(255),
            LogonType NVARCHAR(50),
            LogonTypeDescription NVARCHAR(100),
            LogonProcessName NVARCHAR(255),
            AuthenticationPackage NVARCHAR(255),
            FailureReason NVARCHAR(500),
            ThreatScore INT,
            SeverityLevel NVARCHAR(50),
            ThreatCategory NVARCHAR(100),
            ThreatName NVARCHAR(500),
            ThreatAction NVARCHAR(100),
            FirewallDirection NVARCHAR(50),
            Protocol NVARCHAR(50),
            DestinationAddress NVARCHAR(50),
            DestinationPort NVARCHAR(10),
            ApplicationPath NVARCHAR(1000),
            ProcessId NVARCHAR(50),
            MFAContext NVARCHAR(100),
            MFASuccess BIT,
            MFAType NVARCHAR(100),
            VulnerabilityCategory NVARCHAR(100),
            VulnerabilitySeverity NVARCHAR(50),
            VulnerabilityTitle NVARCHAR(500),
            CVEID NVARCHAR(50),
            EndpointThreatSeverity NVARCHAR(50),
            EndpointThreatCategory NVARCHAR(100),
            FilePath NVARCHAR(1000),
            DetectionUser NVARCHAR(255),
            AuditTrailStatus NVARCHAR(100),
            AuditHealthScore DECIMAL(5,2),
            Alerts NVARCHAR(MAX),
            Recommendation NVARCHAR(MAX),
            AnalysisMetadata NVARCHAR(MAX),
            Dimensions NVARCHAR(MAX),
            RawMessage NVARCHAR(MAX),
            CollectionMethod NVARCHAR(100)
        );
        
        COMMIT TRANSACTION;
        
        SELECT @@ROWCOUNT AS RowsInserted;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;
        
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
    END CATCH
END;
GO

-- Procedure: Insert Network Metric (Bulk)
CREATE OR ALTER PROCEDURE dbo.usp_InsertNetworkMetricsBulk
    @MetricsJSON NVARCHAR(MAX)
AS
BEGIN
    SET NOCOUNT ON;
    
    BEGIN TRY
        BEGIN TRANSACTION;
        
        INSERT INTO dbo.NetworkMetrics (
            CollectionTime, MeasurementTime, MonitoringHost, MonitoringHostIP,
            MetricKey, MetricValue, MetricUnit,
            TargetHost, TargetName, TargetIP, TargetPort,
            MetricCategory, MetricType,
            PingLatency, PacketLoss, Jitter, Availability,
            SSLHandshakeTime, CertificateExpiryDays, CertificateIssuer, CertificateSubject, TLSSuccess,
            DNSResolutionTime, DNSServer, TestDomain,
            DownloadSpeed, UploadSpeed, DownloadMbps, UploadMbps,
            PacketsReceived, PacketsSent, ErrorsReceived, ErrorsSent, DropsReceived, DropsSent,
            InterfaceName, InterfaceStatus, InterfaceSpeed, InterfaceMTU, IPv4Addresses, IPv6Addresses,
            ConnectionStatus, ConnectionType, TotalConnections, UniqueRemoteHosts, UniqueLocalPorts,
            ProcessName, ProcessID, ProcessConnectionCount,
            WANLinkType, WANAvailability, WANLatency, WANPacketLoss, WANStatus, WANHealthScore,
            HTTPStatusCode, HTTPResponseTime, HTTPThroughput, HTTPContentSize,
            PerformanceScore, HealthStatus,
            Dimensions, CollectionMethod, SampleCount
        )
        SELECT 
            ISNULL(CollectionTime, GETDATE()),
            ISNULL(MeasurementTime, GETDATE()),
            MonitoringHost,
            MonitoringHostIP,
            MetricKey,
            MetricValue,
            MetricUnit,
            TargetHost,
            TargetName,
            TargetIP,
            TargetPort,
            MetricCategory,
            MetricType,
            PingLatency,
            PacketLoss,
            Jitter,
            Availability,
            SSLHandshakeTime,
            CertificateExpiryDays,
            CertificateIssuer,
            CertificateSubject,
            TLSSuccess,
            DNSResolutionTime,
            DNSServer,
            TestDomain,
            DownloadSpeed,
            UploadSpeed,
            DownloadMbps,
            UploadMbps,
            PacketsReceived,
            PacketsSent,
            ErrorsReceived,
            ErrorsSent,
            DropsReceived,
            DropsSent,
            InterfaceName,
            InterfaceStatus,
            InterfaceSpeed,
            InterfaceMTU,
            IPv4Addresses,
            IPv6Addresses,
            ConnectionStatus,
            ConnectionType,
            TotalConnections,
            UniqueRemoteHosts,
            UniqueLocalPorts,
            ProcessName,
            ProcessID,
            ProcessConnectionCount,
            WANLinkType,
            WANAvailability,
            WANLatency,
            WANPacketLoss,
            WANStatus,
            WANHealthScore,
            HTTPStatusCode,
            HTTPResponseTime,
            HTTPThroughput,
            HTTPContentSize,
            PerformanceScore,
            HealthStatus,
            Dimensions,
            CollectionMethod,
            SampleCount
        FROM OPENJSON(@MetricsJSON)
        WITH (
            CollectionTime DATETIME2,
            MeasurementTime DATETIME2,
            MonitoringHost NVARCHAR(255),
            MonitoringHostIP NVARCHAR(50),
            MetricKey NVARCHAR(500),
            MetricValue DECIMAL(18,4),
            MetricUnit NVARCHAR(50),
            TargetHost NVARCHAR(255),
            TargetName NVARCHAR(255),
            TargetIP NVARCHAR(50),
            TargetPort INT,
            MetricCategory NVARCHAR(100),
            MetricType NVARCHAR(100),
            PingLatency DECIMAL(10,3),
            PacketLoss DECIMAL(5,2),
            Jitter DECIMAL(10,3),
            Availability BIT,
            SSLHandshakeTime DECIMAL(10,3),
            CertificateExpiryDays INT,
            CertificateIssuer NVARCHAR(500),
            CertificateSubject NVARCHAR(500),
            TLSSuccess BIT,
            DNSResolutionTime DECIMAL(10,3),
            DNSServer NVARCHAR(50),
            TestDomain NVARCHAR(255),
            DownloadSpeed DECIMAL(18,4),
            UploadSpeed DECIMAL(18,4),
            DownloadMbps DECIMAL(10,2),
            UploadMbps DECIMAL(10,2),
            PacketsReceived BIGINT,
            PacketsSent BIGINT,
            ErrorsReceived BIGINT,
            ErrorsSent BIGINT,
            DropsReceived BIGINT,
            DropsSent BIGINT,
            InterfaceName NVARCHAR(255),
            InterfaceStatus NVARCHAR(50),
            InterfaceSpeed BIGINT,
            InterfaceMTU INT,
            IPv4Addresses INT,
            IPv6Addresses INT,
            ConnectionStatus NVARCHAR(100),
            ConnectionType NVARCHAR(100),
            TotalConnections INT,
            UniqueRemoteHosts INT,
            UniqueLocalPorts INT,
            ProcessName NVARCHAR(255),
            ProcessID INT,
            ProcessConnectionCount INT,
            WANLinkType NVARCHAR(100),
            WANAvailability DECIMAL(5,2),
            WANLatency DECIMAL(10,3),
            WANPacketLoss DECIMAL(5,2),
            WANStatus NVARCHAR(50),
            WANHealthScore DECIMAL(5,2),
            HTTPStatusCode INT,
            HTTPResponseTime DECIMAL(10,3),
            HTTPThroughput DECIMAL(18,4),
            HTTPContentSize DECIMAL(18,4),
            PerformanceScore DECIMAL(5,2),
            HealthStatus NVARCHAR(50),
            Dimensions NVARCHAR(MAX),
            CollectionMethod NVARCHAR(100),
            SampleCount INT
        );
        
        COMMIT TRANSACTION;
        
        SELECT @@ROWCOUNT AS RowsInserted;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0
            ROLLBACK TRANSACTION;
        
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        DECLARE @ErrorSeverity INT = ERROR_SEVERITY();
        DECLARE @ErrorState INT = ERROR_STATE();
        
        RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState);
    END CATCH
END;
GO

-- ===================================================================
--                  DATA RETENTION & CLEANUP
-- ===================================================================

-- Procedure: Cleanup Old Metrics
CREATE OR ALTER PROCEDURE dbo.usp_CleanupOldMetrics
    @RetentionDays INT = 90
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @CutoffDate DATETIME2 = DATEADD(DAY, -@RetentionDays, GETDATE());
    DECLARE @SecurityRowsDeleted INT;
    DECLARE @NetworkRowsDeleted INT;
    
    BEGIN TRY
        -- Cleanup SecurityMetrics
        DELETE FROM dbo.SecurityMetrics
        WHERE CollectionTime < @CutoffDate;
        
        SET @SecurityRowsDeleted = @@ROWCOUNT;
        
        -- Cleanup NetworkMetrics
        DELETE FROM dbo.NetworkMetrics
        WHERE CollectionTime < @CutoffDate;
        
        SET @NetworkRowsDeleted = @@ROWCOUNT;
        
        SELECT 
            @SecurityRowsDeleted AS SecurityMetricsDeleted,
            @NetworkRowsDeleted AS NetworkMetricsDeleted,
            @CutoffDate AS CutoffDate;
    END TRY
    BEGIN CATCH
        DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE();
        RAISERROR(@ErrorMessage, 16, 1);
    END CATCH
END;
GO

-- ===================================================================
--                  VERIFICATION QUERIES
-- ===================================================================

PRINT 'Database schema created successfully!';
PRINT '';
PRINT 'Tables created:';
PRINT '  - dbo.SecurityMetrics';
PRINT '  - dbo.NetworkMetrics';
PRINT '';
PRINT 'Views created:';
PRINT '  - dbo.vw_RecentSecurityThreats';
PRINT '  - dbo.vw_NetworkPerformanceSummary';
PRINT '  - dbo.vw_FailedLogonAnalysis';
PRINT '  - dbo.vw_FirewallActivitySummary';
PRINT '  - dbo.vw_EndpointThreatDetection';
PRINT '  - dbo.vw_BandwidthUsageTrends';
PRINT '';
PRINT 'Stored Procedures created:';
PRINT '  - dbo.usp_InsertSecurityMetricsBulk';
PRINT '  - dbo.usp_InsertNetworkMetricsBulk';
PRINT '  - dbo.usp_CleanupOldMetrics';
GO