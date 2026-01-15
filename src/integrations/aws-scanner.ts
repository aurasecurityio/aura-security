/**
 * AWS Security Scanner
 * Scans AWS infrastructure for security issues:
 * - IAM: overly permissive policies, unused credentials, MFA status
 * - S3: public buckets, unencrypted buckets, versioning
 * - EC2: security groups, public IPs, unencrypted volumes
 * - Lambda: public functions, environment secrets
 * - RDS: public instances, unencrypted databases
 */

import {
  IAMClient,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
  ListAttachedUserPoliciesCommand,
  ListUserPoliciesCommand,
  GetPolicyVersionCommand,
  ListPoliciesCommand,
  type User,
  type AccessKeyMetadata,
} from '@aws-sdk/client-iam';

import {
  S3Client,
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
  type Bucket,
} from '@aws-sdk/client-s3';

import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  DescribeVolumesCommand,
  type SecurityGroup,
  type Instance,
  type Volume,
} from '@aws-sdk/client-ec2';

import {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionCommand,
  GetPolicyCommand,
  type FunctionConfiguration,
} from '@aws-sdk/client-lambda';

import {
  RDSClient,
  DescribeDBInstancesCommand,
  type DBInstance,
} from '@aws-sdk/client-rds';

import { fromEnv, fromIni } from '@aws-sdk/credential-providers';

// ============ TYPES ============

export interface AWSFinding {
  service: 'iam' | 's3' | 'ec2' | 'lambda' | 'rds';
  resourceType: string;
  resourceId: string;
  resourceArn?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
}

export interface AWSScanConfig {
  region?: string;
  profile?: string;
  services?: ('iam' | 's3' | 'ec2' | 'lambda' | 'rds')[];
  skipServices?: ('iam' | 's3' | 'ec2' | 'lambda' | 'rds')[];
}

export interface AWSScanResult {
  timestamp: string;
  region: string;
  accountId?: string;
  findings: AWSFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  scannedServices: string[];
  errors: Array<{ service: string; error: string }>;
}

// ============ SCANNER CLASS ============

export class AWSScanner {
  private region: string;
  private iamClient: IAMClient;
  private s3Client: S3Client;
  private ec2Client: EC2Client;
  private lambdaClient: LambdaClient;
  private rdsClient: RDSClient;
  private config: AWSScanConfig;

  constructor(config: AWSScanConfig = {}) {
    this.config = config;
    this.region = config.region || process.env.AWS_REGION || 'us-east-1';

    // Configure credentials
    const credentialProvider = config.profile
      ? fromIni({ profile: config.profile })
      : fromEnv();

    const clientConfig = {
      region: this.region,
      credentials: credentialProvider,
    };

    // Initialize clients
    this.iamClient = new IAMClient(clientConfig);
    this.s3Client = new S3Client(clientConfig);
    this.ec2Client = new EC2Client(clientConfig);
    this.lambdaClient = new LambdaClient(clientConfig);
    this.rdsClient = new RDSClient(clientConfig);
  }

  async scan(): Promise<AWSScanResult> {
    const findings: AWSFinding[] = [];
    const errors: Array<{ service: string; error: string }> = [];
    const scannedServices: string[] = [];

    const services = this.config.services || ['iam', 's3', 'ec2', 'lambda', 'rds'];
    const skip = this.config.skipServices || [];

    console.log(`[AWS] Starting scan in region: ${this.region}`);

    // IAM Scan
    if (services.includes('iam') && !skip.includes('iam')) {
      try {
        console.log('[AWS] Scanning IAM...');
        const iamFindings = await this.scanIAM();
        findings.push(...iamFindings);
        scannedServices.push('iam');
        console.log(`[AWS] IAM: found ${iamFindings.length} findings`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        errors.push({ service: 'iam', error: errorMsg });
        console.error(`[AWS] IAM scan error: ${errorMsg}`);
      }
    }

    // S3 Scan
    if (services.includes('s3') && !skip.includes('s3')) {
      try {
        console.log('[AWS] Scanning S3...');
        const s3Findings = await this.scanS3();
        findings.push(...s3Findings);
        scannedServices.push('s3');
        console.log(`[AWS] S3: found ${s3Findings.length} findings`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        errors.push({ service: 's3', error: errorMsg });
        console.error(`[AWS] S3 scan error: ${errorMsg}`);
      }
    }

    // EC2 Scan
    if (services.includes('ec2') && !skip.includes('ec2')) {
      try {
        console.log('[AWS] Scanning EC2...');
        const ec2Findings = await this.scanEC2();
        findings.push(...ec2Findings);
        scannedServices.push('ec2');
        console.log(`[AWS] EC2: found ${ec2Findings.length} findings`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        errors.push({ service: 'ec2', error: errorMsg });
        console.error(`[AWS] EC2 scan error: ${errorMsg}`);
      }
    }

    // Lambda Scan
    if (services.includes('lambda') && !skip.includes('lambda')) {
      try {
        console.log('[AWS] Scanning Lambda...');
        const lambdaFindings = await this.scanLambda();
        findings.push(...lambdaFindings);
        scannedServices.push('lambda');
        console.log(`[AWS] Lambda: found ${lambdaFindings.length} findings`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        errors.push({ service: 'lambda', error: errorMsg });
        console.error(`[AWS] Lambda scan error: ${errorMsg}`);
      }
    }

    // RDS Scan
    if (services.includes('rds') && !skip.includes('rds')) {
      try {
        console.log('[AWS] Scanning RDS...');
        const rdsFindings = await this.scanRDS();
        findings.push(...rdsFindings);
        scannedServices.push('rds');
        console.log(`[AWS] RDS: found ${rdsFindings.length} findings`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        errors.push({ service: 'rds', error: errorMsg });
        console.error(`[AWS] RDS scan error: ${errorMsg}`);
      }
    }

    // Calculate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length,
    };

    console.log(`[AWS] Scan complete. Total findings: ${findings.length}`);

    return {
      timestamp: new Date().toISOString(),
      region: this.region,
      findings,
      summary,
      scannedServices,
      errors,
    };
  }

  // ============ IAM SCANNING ============

  private async scanIAM(): Promise<AWSFinding[]> {
    const findings: AWSFinding[] = [];

    // List all users
    const usersResponse = await this.iamClient.send(new ListUsersCommand({}));
    const users = usersResponse.Users || [];

    for (const user of users) {
      if (!user.UserName) continue;

      // Check for MFA
      const mfaResponse = await this.iamClient.send(
        new ListMFADevicesCommand({ UserName: user.UserName })
      );
      if (!mfaResponse.MFADevices || mfaResponse.MFADevices.length === 0) {
        findings.push({
          service: 'iam',
          resourceType: 'User',
          resourceId: user.UserName,
          resourceArn: user.Arn,
          severity: 'high',
          title: 'IAM User without MFA',
          description: `User ${user.UserName} does not have MFA enabled`,
          remediation: 'Enable MFA for this IAM user',
          metadata: { userId: user.UserId },
        });
      }

      // Check access keys
      const keysResponse = await this.iamClient.send(
        new ListAccessKeysCommand({ UserName: user.UserName })
      );
      const accessKeys = keysResponse.AccessKeyMetadata || [];

      for (const key of accessKeys) {
        if (!key.AccessKeyId) continue;

        // Check key age (over 90 days is a concern)
        if (key.CreateDate) {
          const keyAge = Date.now() - key.CreateDate.getTime();
          const daysOld = Math.floor(keyAge / (1000 * 60 * 60 * 24));

          if (daysOld > 90) {
            findings.push({
              service: 'iam',
              resourceType: 'AccessKey',
              resourceId: key.AccessKeyId,
              severity: 'medium',
              title: 'Old IAM Access Key',
              description: `Access key ${key.AccessKeyId} for user ${user.UserName} is ${daysOld} days old`,
              remediation: 'Rotate access keys regularly (every 90 days)',
              metadata: { userName: user.UserName, daysOld },
            });
          }
        }

        // Check if key was recently used
        try {
          const lastUsedResponse = await this.iamClient.send(
            new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId })
          );
          const lastUsed = lastUsedResponse.AccessKeyLastUsed?.LastUsedDate;

          if (lastUsed) {
            const daysSinceUse = Math.floor(
              (Date.now() - lastUsed.getTime()) / (1000 * 60 * 60 * 24)
            );

            if (daysSinceUse > 90) {
              findings.push({
                service: 'iam',
                resourceType: 'AccessKey',
                resourceId: key.AccessKeyId,
                severity: 'medium',
                title: 'Unused IAM Access Key',
                description: `Access key ${key.AccessKeyId} for user ${user.UserName} has not been used in ${daysSinceUse} days`,
                remediation: 'Delete unused access keys',
                metadata: { userName: user.UserName, daysSinceUse },
              });
            }
          }
        } catch {
          // Ignore errors checking last used
        }
      }
    }

    // Check for overly permissive policies
    try {
      const policiesResponse = await this.iamClient.send(
        new ListPoliciesCommand({ Scope: 'Local' })
      );
      const policies = policiesResponse.Policies || [];

      for (const policy of policies) {
        if (!policy.Arn || !policy.DefaultVersionId) continue;

        try {
          const versionResponse = await this.iamClient.send(
            new GetPolicyVersionCommand({
              PolicyArn: policy.Arn,
              VersionId: policy.DefaultVersionId,
            })
          );

          const document = versionResponse.PolicyVersion?.Document;
          if (document) {
            const policyDoc = JSON.parse(decodeURIComponent(document));
            const statements = policyDoc.Statement || [];

            for (const statement of statements) {
              if (
                statement.Effect === 'Allow' &&
                statement.Action === '*' &&
                statement.Resource === '*'
              ) {
                findings.push({
                  service: 'iam',
                  resourceType: 'Policy',
                  resourceId: policy.PolicyName || policy.Arn,
                  resourceArn: policy.Arn,
                  severity: 'critical',
                  title: 'Overly Permissive IAM Policy',
                  description: `Policy ${policy.PolicyName} grants full access (Action: *, Resource: *)`,
                  remediation: 'Apply least privilege principle - limit actions and resources',
                });
              }
            }
          }
        } catch {
          // Ignore policy parsing errors
        }
      }
    } catch {
      // Ignore errors listing policies
    }

    return findings;
  }

  // ============ S3 SCANNING ============

  private async scanS3(): Promise<AWSFinding[]> {
    const findings: AWSFinding[] = [];

    // List all buckets
    const bucketsResponse = await this.s3Client.send(new ListBucketsCommand({}));
    const buckets = bucketsResponse.Buckets || [];

    for (const bucket of buckets) {
      if (!bucket.Name) continue;

      // Check public access block
      try {
        const publicAccessResponse = await this.s3Client.send(
          new GetPublicAccessBlockCommand({ Bucket: bucket.Name })
        );
        const config = publicAccessResponse.PublicAccessBlockConfiguration;

        if (
          !config?.BlockPublicAcls ||
          !config?.BlockPublicPolicy ||
          !config?.IgnorePublicAcls ||
          !config?.RestrictPublicBuckets
        ) {
          findings.push({
            service: 's3',
            resourceType: 'Bucket',
            resourceId: bucket.Name,
            severity: 'high',
            title: 'S3 Bucket Public Access Not Fully Blocked',
            description: `Bucket ${bucket.Name} does not have all public access blocks enabled`,
            remediation: 'Enable all public access block settings',
            metadata: {
              blockPublicAcls: config?.BlockPublicAcls,
              blockPublicPolicy: config?.BlockPublicPolicy,
              ignorePublicAcls: config?.IgnorePublicAcls,
              restrictPublicBuckets: config?.RestrictPublicBuckets,
            },
          });
        }
      } catch (err) {
        // If public access block is not configured, it's a finding
        if ((err as Error).name === 'NoSuchPublicAccessBlockConfiguration') {
          findings.push({
            service: 's3',
            resourceType: 'Bucket',
            resourceId: bucket.Name,
            severity: 'high',
            title: 'S3 Bucket No Public Access Block',
            description: `Bucket ${bucket.Name} has no public access block configuration`,
            remediation: 'Configure public access block for this bucket',
          });
        }
      }

      // Check encryption
      try {
        await this.s3Client.send(
          new GetBucketEncryptionCommand({ Bucket: bucket.Name })
        );
        // If we get here, encryption is configured
      } catch (err) {
        if (
          (err as Error).name === 'ServerSideEncryptionConfigurationNotFoundError'
        ) {
          findings.push({
            service: 's3',
            resourceType: 'Bucket',
            resourceId: bucket.Name,
            severity: 'medium',
            title: 'S3 Bucket Not Encrypted',
            description: `Bucket ${bucket.Name} does not have default encryption enabled`,
            remediation: 'Enable server-side encryption for this bucket',
          });
        }
      }

      // Check versioning
      try {
        const versioningResponse = await this.s3Client.send(
          new GetBucketVersioningCommand({ Bucket: bucket.Name })
        );
        if (versioningResponse.Status !== 'Enabled') {
          findings.push({
            service: 's3',
            resourceType: 'Bucket',
            resourceId: bucket.Name,
            severity: 'low',
            title: 'S3 Bucket Versioning Disabled',
            description: `Bucket ${bucket.Name} does not have versioning enabled`,
            remediation: 'Enable versioning for data protection and recovery',
          });
        }
      } catch {
        // Ignore versioning check errors
      }

      // Check for public bucket policy
      try {
        const policyStatusResponse = await this.s3Client.send(
          new GetBucketPolicyStatusCommand({ Bucket: bucket.Name })
        );
        if (policyStatusResponse.PolicyStatus?.IsPublic) {
          findings.push({
            service: 's3',
            resourceType: 'Bucket',
            resourceId: bucket.Name,
            severity: 'critical',
            title: 'S3 Bucket Has Public Policy',
            description: `Bucket ${bucket.Name} has a policy that makes it publicly accessible`,
            remediation: 'Review and restrict the bucket policy',
          });
        }
      } catch {
        // No policy or error - skip
      }
    }

    return findings;
  }

  // ============ EC2 SCANNING ============

  private async scanEC2(): Promise<AWSFinding[]> {
    const findings: AWSFinding[] = [];

    // Check security groups
    const sgResponse = await this.ec2Client.send(
      new DescribeSecurityGroupsCommand({})
    );
    const securityGroups = sgResponse.SecurityGroups || [];

    for (const sg of securityGroups) {
      if (!sg.GroupId) continue;

      // Check for overly permissive inbound rules
      for (const rule of sg.IpPermissions || []) {
        for (const ipRange of rule.IpRanges || []) {
          if (ipRange.CidrIp === '0.0.0.0/0') {
            // Check if it's a sensitive port
            const fromPort = rule.FromPort || 0;
            const toPort = rule.ToPort || 65535;
            const sensitivePort = this.isSensitivePort(fromPort, toPort);

            if (sensitivePort) {
              findings.push({
                service: 'ec2',
                resourceType: 'SecurityGroup',
                resourceId: sg.GroupId,
                severity: 'critical',
                title: 'Security Group Allows Public Access to Sensitive Port',
                description: `Security group ${sg.GroupName || sg.GroupId} allows 0.0.0.0/0 access to port ${fromPort}-${toPort}`,
                remediation: 'Restrict access to specific IP ranges',
                metadata: {
                  groupName: sg.GroupName,
                  fromPort,
                  toPort,
                  protocol: rule.IpProtocol,
                },
              });
            } else if (fromPort === 0 && toPort === 65535) {
              findings.push({
                service: 'ec2',
                resourceType: 'SecurityGroup',
                resourceId: sg.GroupId,
                severity: 'high',
                title: 'Security Group Allows All Traffic from Internet',
                description: `Security group ${sg.GroupName || sg.GroupId} allows all inbound traffic from 0.0.0.0/0`,
                remediation: 'Restrict to specific ports and IP ranges',
                metadata: { groupName: sg.GroupName },
              });
            }
          }
        }
      }
    }

    // Check instances
    const instancesResponse = await this.ec2Client.send(
      new DescribeInstancesCommand({})
    );
    const reservations = instancesResponse.Reservations || [];

    for (const reservation of reservations) {
      for (const instance of reservation.Instances || []) {
        if (!instance.InstanceId) continue;

        // Check for public IP
        if (instance.PublicIpAddress) {
          findings.push({
            service: 'ec2',
            resourceType: 'Instance',
            resourceId: instance.InstanceId,
            severity: 'info',
            title: 'EC2 Instance Has Public IP',
            description: `Instance ${instance.InstanceId} has public IP ${instance.PublicIpAddress}`,
            remediation: 'Verify this instance needs public access',
            metadata: {
              publicIp: instance.PublicIpAddress,
              instanceType: instance.InstanceType,
            },
          });
        }
      }
    }

    // Check for unencrypted volumes
    const volumesResponse = await this.ec2Client.send(
      new DescribeVolumesCommand({})
    );
    const volumes = volumesResponse.Volumes || [];

    for (const volume of volumes) {
      if (!volume.VolumeId) continue;

      if (!volume.Encrypted) {
        findings.push({
          service: 'ec2',
          resourceType: 'Volume',
          resourceId: volume.VolumeId,
          severity: 'medium',
          title: 'EBS Volume Not Encrypted',
          description: `Volume ${volume.VolumeId} is not encrypted`,
          remediation: 'Enable encryption for EBS volumes',
          metadata: {
            size: volume.Size,
            state: volume.State,
          },
        });
      }
    }

    return findings;
  }

  private isSensitivePort(fromPort: number, toPort: number): boolean {
    const sensitivePorts = [22, 23, 3389, 3306, 5432, 1433, 27017, 6379];
    return sensitivePorts.some(p => p >= fromPort && p <= toPort);
  }

  // ============ LAMBDA SCANNING ============

  private async scanLambda(): Promise<AWSFinding[]> {
    const findings: AWSFinding[] = [];

    // List functions
    const functionsResponse = await this.lambdaClient.send(
      new ListFunctionsCommand({})
    );
    const functions = functionsResponse.Functions || [];

    for (const func of functions) {
      if (!func.FunctionName || !func.FunctionArn) continue;

      // Check for environment variables that look like secrets
      const envVars = func.Environment?.Variables || {};
      for (const [key, value] of Object.entries(envVars)) {
        const keyLower = key.toLowerCase();
        if (
          keyLower.includes('secret') ||
          keyLower.includes('password') ||
          keyLower.includes('key') ||
          keyLower.includes('token')
        ) {
          findings.push({
            service: 'lambda',
            resourceType: 'Function',
            resourceId: func.FunctionName,
            resourceArn: func.FunctionArn,
            severity: 'high',
            title: 'Lambda Function Has Sensitive Environment Variable',
            description: `Function ${func.FunctionName} has environment variable "${key}" that may contain secrets`,
            remediation: 'Use AWS Secrets Manager or Parameter Store for sensitive values',
            metadata: { envVarName: key },
          });
        }
      }

      // Check for public resource policy
      try {
        const policyResponse = await this.lambdaClient.send(
          new GetPolicyCommand({ FunctionName: func.FunctionName })
        );
        if (policyResponse.Policy) {
          const policy = JSON.parse(policyResponse.Policy);
          for (const statement of policy.Statement || []) {
            if (statement.Principal === '*') {
              findings.push({
                service: 'lambda',
                resourceType: 'Function',
                resourceId: func.FunctionName,
                resourceArn: func.FunctionArn,
                severity: 'critical',
                title: 'Lambda Function Has Public Access',
                description: `Function ${func.FunctionName} has a resource policy allowing public access`,
                remediation: 'Restrict the resource policy to specific principals',
              });
              break;
            }
          }
        }
      } catch {
        // No policy - that's fine
      }

      // Check runtime (old runtimes are security risks)
      const runtime = func.Runtime || '';
      const deprecatedRuntimes = [
        'nodejs12.x',
        'nodejs10.x',
        'python2.7',
        'python3.6',
        'ruby2.5',
      ];
      if (deprecatedRuntimes.some(r => runtime.includes(r))) {
        findings.push({
          service: 'lambda',
          resourceType: 'Function',
          resourceId: func.FunctionName,
          resourceArn: func.FunctionArn,
          severity: 'medium',
          title: 'Lambda Function Uses Deprecated Runtime',
          description: `Function ${func.FunctionName} uses deprecated runtime ${runtime}`,
          remediation: 'Upgrade to a supported runtime version',
          metadata: { runtime },
        });
      }
    }

    return findings;
  }

  // ============ RDS SCANNING ============

  private async scanRDS(): Promise<AWSFinding[]> {
    const findings: AWSFinding[] = [];

    // List DB instances
    const dbResponse = await this.rdsClient.send(
      new DescribeDBInstancesCommand({})
    );
    const instances = dbResponse.DBInstances || [];

    for (const db of instances) {
      if (!db.DBInstanceIdentifier) continue;

      // Check for public access
      if (db.PubliclyAccessible) {
        findings.push({
          service: 'rds',
          resourceType: 'DBInstance',
          resourceId: db.DBInstanceIdentifier,
          resourceArn: db.DBInstanceArn,
          severity: 'critical',
          title: 'RDS Instance Publicly Accessible',
          description: `Database ${db.DBInstanceIdentifier} is publicly accessible`,
          remediation: 'Disable public accessibility unless required',
          metadata: {
            engine: db.Engine,
            endpoint: db.Endpoint?.Address,
          },
        });
      }

      // Check for encryption
      if (!db.StorageEncrypted) {
        findings.push({
          service: 'rds',
          resourceType: 'DBInstance',
          resourceId: db.DBInstanceIdentifier,
          resourceArn: db.DBInstanceArn,
          severity: 'high',
          title: 'RDS Instance Not Encrypted',
          description: `Database ${db.DBInstanceIdentifier} storage is not encrypted`,
          remediation: 'Enable storage encryption for the database',
          metadata: { engine: db.Engine },
        });
      }

      // Check for automated backups
      if (db.BackupRetentionPeriod === 0) {
        findings.push({
          service: 'rds',
          resourceType: 'DBInstance',
          resourceId: db.DBInstanceIdentifier,
          resourceArn: db.DBInstanceArn,
          severity: 'medium',
          title: 'RDS Instance Has No Automated Backups',
          description: `Database ${db.DBInstanceIdentifier} has automated backups disabled`,
          remediation: 'Enable automated backups with appropriate retention period',
          metadata: { engine: db.Engine },
        });
      }

      // Check for deletion protection
      if (!db.DeletionProtection) {
        findings.push({
          service: 'rds',
          resourceType: 'DBInstance',
          resourceId: db.DBInstanceIdentifier,
          resourceArn: db.DBInstanceArn,
          severity: 'low',
          title: 'RDS Instance Has No Deletion Protection',
          description: `Database ${db.DBInstanceIdentifier} does not have deletion protection enabled`,
          remediation: 'Enable deletion protection for production databases',
          metadata: { engine: db.Engine },
        });
      }
    }

    return findings;
  }
}

// Quick scan function
export async function scanAWS(config?: AWSScanConfig): Promise<AWSScanResult> {
  const scanner = new AWSScanner(config);
  return scanner.scan();
}
