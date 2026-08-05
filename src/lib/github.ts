const GITHUB_API = 'https://api.github.com';
const USERNAME = 'JuttSahib1999';

// Repositories that should NOT appear in the Projects page
const HIDDEN_REPOSITORIES = [
  'JuttSahib1999.github.io',
  'JuttSahib1999',
];

// Helper to add delay between retries
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function getUserProfile() {
  try {
    const response = await fetch(`${GITHUB_API}/users/${USERNAME}`, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Portfolio-App',
      },
    });

    if (!response.ok) {
      console.error('GitHub profile API error:', response.status);
      return null;
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching GitHub profile:', error);
    return null;
  }
}

export async function getAllRepositories() {
  // First try: fetch from GitHub API
  try {
    console.log('Fetching repositories from GitHub API...');

    const response = await fetch(
      `${GITHUB_API}/users/${USERNAME}/repos?per_page=100&sort=updated&type=public`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Portfolio-App',
        },
      }
    );

    if (response.ok) {
      const repos = await response.json();

      // Hide only selected repositories
      const filteredRepos = repos.filter(
        (repo: any) => !HIDDEN_REPOSITORIES.includes(repo.name)
      );

      console.log(
        `Successfully fetched ${filteredRepos.length} repositories from GitHub`
      );

      return filteredRepos;
    }

    console.error('GitHub API returned status:', response.status);

    // If rate limited, wait and retry once
    if (response.status === 403) {
      console.log('Rate limited. Waiting 2 seconds and retrying...');
      await delay(2000);

      const retryResponse = await fetch(
        `${GITHUB_API}/users/${USERNAME}/repos?per_page=100&sort=updated&type=public`,
        {
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Portfolio-App-2',
          },
        }
      );

      if (retryResponse.ok) {
        const repos = await retryResponse.json();

        // Hide only selected repositories
        const filteredRepos = repos.filter(
          (repo: any) => !HIDDEN_REPOSITORIES.includes(repo.name)
        );

        console.log(
          `Successfully fetched ${filteredRepos.length} repositories on retry`
        );

        return filteredRepos;
      }
    }
  } catch (error) {
    console.error('Error fetching repositories:', error);
  }

  // Fallback: Return empty array (no sample data)
  console.log('Unable to fetch repositories. Returning empty list.');
  return [];
}

export async function getRepositoryReadme(repoName: string): Promise<string | null> {
  try {
    const response = await fetch(
      `${GITHUB_API}/repos/${USERNAME}/${repoName}/readme`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Portfolio-App',
        },
      }
    );

    if (!response.ok) return null;

    const data = await response.json();

    if (data.content) {
      return Buffer.from(data.content, 'base64').toString('utf-8');
    }

    return null;
  } catch (error) {
    console.error('Error fetching README:', error);
    return null;
  }
}
