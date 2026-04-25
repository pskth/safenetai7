// PhishGuard Popup Script
document.addEventListener('DOMContentLoaded', async function() {
  const lastUpdate = document.getElementById('last-update');
  const openDashboard = document.getElementById('open-dashboard');
  const totalDetectedEl = document.getElementById('total-detected');
  const userReportsEl = document.getElementById('user-reports');

  // Load stats from storage
  chrome.storage.local.get(['lastUpdate'], function(data) {
    if (lastUpdate) {
      const date = data.lastUpdate ? new Date(data.lastUpdate).toLocaleString() : 'Never';
      lastUpdate.textContent = date;
    }
  });

  // Fetch global stats
  try {
    const res = await fetch('http://localhost:3000/api/trpc/scan.publicStats');
    if (res.ok) {
      const responseBody = await res.json();
      // tRPC with SuperJSON nests the data under `.json`
      const stats = responseBody?.result?.data?.json || responseBody?.result?.data;
      if (stats && totalDetectedEl && userReportsEl) {
        totalDetectedEl.textContent = stats.totalDetectedGlobal?.toLocaleString() ?? '0';
        userReportsEl.textContent = stats.userReportsGlobal?.toLocaleString() ?? '0';
      }
    }
  } catch (err) {
    console.error('Failed to fetch stats:', err);
  }

  // Open dashboard button
  if (openDashboard) {
    openDashboard.addEventListener('click', function() {
      chrome.tabs.create({ url: 'http://localhost:3000/dashboard' });
    });
  }
});
