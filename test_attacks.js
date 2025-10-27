/**
 * test_attacks.js - Automated Attack Simulation Script
 * Tests all attack types against existing users in weak mode
 */

const http = require('http');

const API_BASE = 'http://localhost:3000';

// Helper: Make HTTP request
function apiRequest(endpoint, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(API_BASE + endpoint);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ ok: res.statusCode === 200, data: JSON.parse(data) });
        } catch (e) {
          resolve({ ok: false, error: 'Invalid JSON response' });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// Test attacks on a user
async function testAttacks(username, ciphertext, cipher, params = {}) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`🎯 Testing attacks on user: ${username}`);
  console.log(`📦 Intercepted ciphertext: ${ciphertext}`);
  console.log(`🔐 Algorithm: ${cipher}`);
  console.log(`${'='.repeat(60)}\n`);

  try {
    const startTime = Date.now();
    
    const result = await apiRequest('/simulate/mitm', 'POST', {
      username,
      intercepted: ciphertext,
      cipher,
      params
    });

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(3);

    if (result.ok && result.data.attacks) {
      console.log(`✅ Attack simulation completed in ${elapsed}s\n`);
      
      for (const attack of result.data.attacks) {
        console.log(`📊 ${attack.type}`);
        console.log(`   Attempts: ${attack.attempts}`);
        console.log(`   Time: ${attack.elapsed}s`);
        
        if (attack.success !== undefined) {
          console.log(`   Success: ${attack.success ? '✓ YES' : '✗ NO'}`);
        }
        
        if (attack.recovered) {
          console.log(`   🔓 RECOVERED PASSWORD: "${attack.recovered}"`);
        }
        
        if (attack.candidates && attack.candidates.length > 0) {
          console.log(`   Top 3 candidates:`);
          attack.candidates.slice(0, 3).forEach((c, i) => {
            if (c.text) {
              console.log(`      ${i+1}. ${JSON.stringify(c.text)} (shift: ${c.shift || c.a})`);
            }
          });
        }

        if (attack.matches && attack.matches.length > 0) {
          console.log(`   📖 Dictionary matches: ${attack.matches.join(', ')}`);
        }

        if (attack.vulnerability) {
          console.log(`   ⚠️  Vulnerability: ${attack.vulnerability.substring(0, 100)}...`);
        }

        console.log('');
      }
    } else {
      console.log(`❌ Attack failed: ${result.error || result.data?.error || 'Unknown error'}\n`);
    }
  } catch (error) {
    console.log(`❌ Error during attack: ${error.message}\n`);
  }
}

// Main test suite
async function runAllTests() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║  🔴 AUTOMATED ATTACK TESTING SUITE                        ║');
  console.log('║  Educational Demonstration of Cryptographic Weaknesses    ║');
  console.log('╚════════════════════════════════════════════════════════════╝');

  // Get existing users
  const fs = require('fs');
  const path = require('path');
  const usersPath = path.join(__dirname, 'backend', 'data', 'users.json');
  
  let users = [];
  try {
    const raw = fs.readFileSync(usersPath, 'utf8');
    users = JSON.parse(raw).users || [];
  } catch (e) {
    console.log('❌ Could not load users.json');
    return;
  }

  if (users.length === 0) {
    console.log('\n⚠️  No users found. Create some users first!\n');
    return;
  }

  console.log(`\n📋 Found ${users.length} user(s) to test\n`);

  for (const user of users) {
    if (user.mode === 'weak') {
      await testAttacks(
        user.username,
        user.storedPassword,
        user.cipher,
        user.params
      );
      
      // Small delay between tests
      await new Promise(resolve => setTimeout(resolve, 500));
    } else {
      console.log(`\n⏭️  Skipping ${user.username} (secure mode - hash cannot be brute-forced efficiently)\n`);
    }
  }

  // Summary
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║  📊 ATTACK TESTING COMPLETE                               ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('\n✅ All attacks executed');
  console.log('📁 Results saved to: backend/data/results.csv');
  console.log('🌐 View full report at: http://localhost:3000\n');
  
  // Display summary from results.csv
  try {
    const resultsPath = path.join(__dirname, 'backend', 'data', 'results.csv');
    const csvContent = fs.readFileSync(resultsPath, 'utf8');
    const lines = csvContent.trim().split('\n');
    
    console.log(`\n📈 Total attacks logged: ${lines.length - 1}`);
    console.log(`\nLast 5 attack results:`);
    console.log('-'.repeat(120));
    
    lines.slice(-6).forEach(line => {
      if (!line.includes('timestamp')) {
        const parts = line.split(',');
        const time = new Date(parts[0]).toLocaleTimeString();
        const user = parts[1];
        const type = parts[2];
        const success = parts[6];
        const recovered = parts[7] || '(none)';
        console.log(`${time} | ${user.padEnd(10)} | ${type.padEnd(25)} | Success: ${success.padEnd(5)} | Recovered: ${recovered}`);
      }
    });
    console.log('-'.repeat(120));
  } catch (e) {
    console.log('Could not read results.csv');
  }

  console.log('\n');
}

// Run
console.log('\n🚀 Starting attack simulation...\n');
setTimeout(runAllTests, 1000); // Wait 1s for server to be ready
