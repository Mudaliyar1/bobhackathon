(function () {
  // Security rationale: the SOC dashboard polls frequently so challenged logins
  // become visible while the attempted takeover is still fresh.
  const totalAttempts = document.querySelector('[data-total-attempts]');
  const successfulSessions = document.querySelector('[data-successful-sessions]');
  const challengesTriggered = document.querySelector('[data-challenges-triggered]');
  const threatsPrevented = document.querySelector('[data-threats-prevented]');
  const currentThreshold = document.querySelector('[data-current-threshold]');
  const thresholdSlider = document.querySelector('[data-threshold-slider]');
  const thresholdValue = document.querySelector('[data-threshold-value]');
  const eventFeed = document.querySelector('[data-event-feed]');
  const attackReplay = document.querySelector('[data-attack-replay]');
  const heatIndicator = document.querySelector('[data-heat-indicator]');
  const dashboardShell = document.querySelector('[data-dashboard-shell]');
  const riskCanvas = document.getElementById('riskDistributionChart');
  let riskChart;
  let previousChallenges = Number(challengesTriggered ? challengesTriggered.textContent : 0);

  function postThreshold(value) {
    return fetch('/api/admin/threshold', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threshold: value })
    }).then((response) => response.json());
  }

  function eventRow(log) {
    const user = log.user_id ? log.user_id.username : 'unknown';
    const reasons = (log.riskReasons || []).map((reason) => reason.label).join(', ') || 'Trusted profile';
    return `
      <div class="feed-item ${log.status === 'CHALLENGED' ? 'feed-danger' : ''}">
        <div>
          <strong>${log.status}</strong>
          <span>${user}</span>
        </div>
        <small>${reasons}</small>
      </div>
    `;
  }

  function replayMarkup(log) {
    if (!log) {
      return '<div class="empty-state">No prevented ATO attempt yet.</div>';
    }

    return (log.replayEvents || []).map((event, index) => `
      <div class="timeline-step">
        <span>${index + 1}</span>
        <strong>${event}</strong>
      </div>
    `).join('');
  }

  function updateChart(buckets) {
    const labels = ['Low', 'Medium', 'High'];
    const values = [buckets.low, buckets.medium, buckets.high];

    if (!riskChart) {
      riskChart = new Chart(riskCanvas, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: ['#22c55e', '#f97316', '#ef233c'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              labels: { color: '#f8fafc' }
            }
          },
          cutout: '68%'
        }
      });
      return;
    }

    riskChart.data.datasets[0].data = values;
    riskChart.update();
  }

  function flashIfNeeded(challengeCount) {
    if (!dashboardShell || challengeCount <= previousChallenges) {
      previousChallenges = challengeCount;
      return;
    }

    dashboardShell.classList.add('threat-flash');
    setTimeout(() => dashboardShell.classList.remove('threat-flash'), 1400);
    previousChallenges = challengeCount;
  }

  function applyData(data) {
    totalAttempts.textContent = data.totalAttempts;
    successfulSessions.textContent = data.successfulSessions;
    challengesTriggered.textContent = data.challengesTriggered;
    threatsPrevented.textContent = data.threatsPrevented;
    currentThreshold.textContent = data.currentThreshold;
    thresholdValue.textContent = data.currentThreshold;
    thresholdSlider.value = data.currentThreshold;
    heatIndicator.textContent = data.heatLevel;
    heatIndicator.dataset.heat = data.heatLevel.toLowerCase();
    eventFeed.innerHTML = data.logs.map(eventRow).join('') || '<div class="empty-state">Awaiting login telemetry.</div>';
    attackReplay.innerHTML = replayMarkup(data.latestThreat);
    updateChart(data.riskBuckets);
    flashIfNeeded(data.challengesTriggered);
  }

  function refresh() {
    fetch('/api/admin/dashboard')
      .then((response) => response.json())
      .then(applyData)
      .catch(() => {});
  }

  if (thresholdSlider) {
    thresholdSlider.addEventListener('input', function () {
      thresholdValue.textContent = thresholdSlider.value;
    });

    thresholdSlider.addEventListener('change', function () {
      postThreshold(thresholdSlider.value).then(refresh);
    });
  }

  if (riskCanvas) {
    refresh();
    setInterval(refresh, 3000);
  }
})();
