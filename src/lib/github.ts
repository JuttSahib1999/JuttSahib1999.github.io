const GITHUB_API = 'https://api.github.com';
const USERNAME = 'JuttSahib1999';

export async function getUserProfile() {
  try {
    const response = await fetch(`${GITHUB_API}/users/${USERNAME}`, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Portfolio-App',
      },
    });
    
    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    console.error('Error fetching GitHub profile:', error);
    return null;
  }
}

export async function getAllRepositories() {
  try {
    const response = await fetch(
      `${GITHUB_API}/users/${USERNAME}/repos?per_page=100&sort=updated&type=public`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Portfolio-App',
        },
      }
    );
    
    if (!response.ok) return [];
    return await response.json();
  } catch (error) {
    console.error('Error fetching repositories:', error);
    return [];
  }
}