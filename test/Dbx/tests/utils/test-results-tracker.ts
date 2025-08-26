/**
 * Shared test results tracker for consistent reporting across test files
 */
import { logger } from './test-logger.js';

export interface TestResult {
  passed: boolean;
  error: Error | null;
  startTime: Date | null;
  endTime: Date | null;
  duration: number | null;
  details: Record<string, any>;
  file: string;
}

class TestResultsTracker {
  private results: Record<string, TestResult> = {};
  private startTime: Date = new Date();

  registerTest(testName: string, file: string): void {
    this.results[`${file}:${testName}`] = {
      passed: false,
      error: null,
      startTime: new Date(),
      endTime: null,
      duration: null,
      details: {},
      file
    };
  }

  updateTestResult(testName: string, file: string, updates: Partial<TestResult>): void {
    const key = `${file}:${testName}`;
    if (this.results[key]) {
      this.results[key] = { ...this.results[key], ...updates };
    }
  }

  markTestPassed(testName: string, file: string, details: Record<string, any> = {}): void {
    const key = `${file}:${testName}`;
    if (this.results[key]) {
      this.results[key].passed = true;
      this.results[key].endTime = new Date();
      this.results[key].duration = this.results[key].endTime.getTime() - 
        (this.results[key].startTime?.getTime() || 0);
      this.results[key].details = { ...this.results[key].details, ...details };
    }
  }

  markTestFailed(testName: string, file: string, error: Error, details: Record<string, any> = {}): void {
    const key = `${file}:${testName}`;
    if (this.results[key]) {
      this.results[key].passed = false;
      this.results[key].error = error;
      this.results[key].endTime = new Date();
      this.results[key].duration = this.results[key].endTime.getTime() - 
        (this.results[key].startTime?.getTime() || 0);
      this.results[key].details = { ...this.results[key].details, ...details };
    }
  }

  addTestDetails(testName: string, file: string, details: Record<string, any>): void {
    const key = `${file}:${testName}`;
    if (this.results[key]) {
      this.results[key].details = { ...this.results[key].details, ...details };
    }
  }

  getTestResult(testName: string, file: string): TestResult | null {
    const key = `${file}:${testName}`;
    return this.results[key] || null;
  }

  getAllResults(): Record<string, TestResult> {
    return this.results;
  }

  getResultsByFile(file: string): Record<string, TestResult> {
    const fileResults: Record<string, TestResult> = {};
    
    Object.entries(this.results).forEach(([key, result]) => {
      if (result.file === file) {
        fileResults[key] = result;
      }
    });
    
    return fileResults;
  }

  printSummary(timestamp: string, folderName: string = ''): void {
    const endTime = new Date();
    const totalDuration = endTime.getTime() - this.startTime.getTime();
    const totalTests = Object.keys(this.results).length;
    const passedTests = Object.values(this.results).filter(r => r.passed).length;

    logger.log('\n=== Test Summary ===');
    logger.log(`Run ID: ${timestamp}`);
    if (folderName) {
      logger.log(`Test Folder: ${folderName}`);
    }
    logger.log('-------------------');

    // Group results by file
    const fileGroups: Record<string, TestResult[]> = {};
    
    Object.values(this.results).forEach(result => {
      if (!fileGroups[result.file]) {
        fileGroups[result.file] = [];
      }
      fileGroups[result.file].push(result);
    });

    // Print results by file
    Object.entries(fileGroups).forEach(([file, results]) => {
      logger.log(`\n[File: ${file}]`);
      
      results.forEach(result => {
        const testName = Object.keys(this.results).find(key => 
          this.results[key] === result
        )?.split(':')[1] || 'Unknown Test';
        
        const icon = result.passed ? '✅' : '❌';
        const status = result.passed ? 'Success' : 'Failed';
        const duration = result.duration ? `${result.duration}ms` : 'N/A';

        logger.log(`\n${icon} ${testName}`);
        logger.log(`   Status: ${status}`);
        logger.log(`   Duration: ${duration}`);

        if (result.error) {
          logger.log(`   Error: ${result.error.message}`);
        }

        if (Object.keys(result.details).length > 0) {
          logger.log('   Details:');
          Object.entries(result.details).forEach(([key, value]) => {
            logger.log(`     ${key}: ${value}`);
          });
        }
      });
    });

    logger.log('\n=== Summary Statistics ===');
    logger.log(`Total Tests: ${totalTests}`);
    logger.log(`Passed: ${passedTests}`);
    logger.log(`Failed: ${totalTests - passedTests}`);
    logger.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);
    logger.log(`Total Duration: ${totalDuration}ms`);
    logger.log('==================\n');
  }

  reset(): void {
    this.results = {};
    this.startTime = new Date();
  }
}

// Singleton instance to be shared across test files
export const testResultsTracker = new TestResultsTracker();
