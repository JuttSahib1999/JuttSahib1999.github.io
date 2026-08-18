const GITHUB_API = 'https://api.github.com';
const USERNAME = 'JuttSahib1999';

/**
 * These repositories are intentionally hidden from the Projects page.
 *
 * JuttSahib1999.github.io = the portfolio website repository
 * JuttSahib1999          = the profile/super repository
 */
const HIDDEN_REPOSITORIES = new Set([
  'JuttSahib1999.github.io',
  'JuttSahib1999',
]);

/**
 * GitHub token is ONLY supplied during the Astro build through
 * GitHub Actions.
 *
 * IMPORTANT:
 * Never hard-code your PAT here.
 */
const GITHUB_TOKEN = process.env.GH_PAT || process.env.GITHUB_TOKEN || '';

function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'JuttSahib1999-Portfolio',
    'X-GitHub-Api-Version': '2022-11-28',
  };

  if (GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${GITHUB_TOKEN}`;
  }

  return headers;
}

function getRateLimitInfo(response: Response) {
  const remaining = response.headers.get('x-ratelimit-remaining');
  const reset = response.headers.get('x-ratelimit-reset');

  return {
    remaining: remaining !== null ? Number(remaining) : null,
    reset: reset !== null ? Number(reset) : null,
  };
}

function getResetDate(unixTimestamp: number | null): string {
  if (!unixTimestamp) {
    return 'unknown';
  }

  return new Date(unixTimestamp * 1000).toISOString();
}

/**
 * Perform a GitHub API request.
 *
 * We deliberately DO NOT retry immediately when rate-limited.
 * GitHub's rate-limit response should be respected instead of
 * sending another request two seconds later.
 */
async function githubFetch(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const headers = {
    ...getHeaders(),
    ...(options.headers || {}),
  };

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (response.status === 403 || response.status === 429) {
    const rateLimit = getRateLimitInfo(response);

    console.error(
      [
        'GitHub API rate limit reached.',
        `Status: ${response.status}`,
        `Remaining: ${rateLimit.remaining ?? 'unknown'}`,
        `Reset: ${getResetDate(rateLimit.reset)}`,
        `Authenticated: ${Boolean(GITHUB_TOKEN)}`,
      ].join(' ')
    );

    throw new Error(
      `GitHub API rate limit reached. ` +
        `Remaining: ${rateLimit.remaining ?? 'unknown'}. ` +
        `Reset: ${getResetDate(rateLimit.reset)}`
    );
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');

    throw new Error(
      `GitHub API request failed: ${response.status} ${response.statusText}` +
        (body ? ` - ${body.slice(0, 500)}` : '')
    );
  }

  return response;
}

/**
 * Fetch the GitHub user profile.
 */
export async function getUserProfile() {
  try {
    const response = await githubFetch(
      `${GITHUB_API}/users/${USERNAME}`
    );

    return await response.json();
  } catch (error) {
    console.error('Error fetching GitHub profile:', error);

    /**
     * The profile is optional for the website.
     * Therefore profile failures do not need to break the entire build.
     */
    return null;
  }
}

/**
 * Fetch ALL public repositories belonging to the user.
 *
 * Improvements over the old implementation:
 *
 * - Authenticated with  when available
 * - Handles pagination
 * - Does not stop at 100 repositories
 * - Excludes hidden repositories
 * - Excludes forks
 * - Does NOT silently return [] when the API fails
 */
export async function getAllRepositories() {
  const allRepositories: any[] = [];

  const perPage = 100;
  let page = 1;

  try {
    console.log(
      `Fetching repositories for GitHub user: ${USERNAME}`
    );

    while (true) {
      const url =
        `${GITHUB_API}/users/${USERNAME}/repos` +
        `?per_page=${perPage}` +
        `&page=${page}` +
        `&sort=updated` +
        `&direction=desc` +
        `&type=owner`;

      const response = await githubFetch(url);

      const repositories = await response.json();

      if (!Array.isArray(repositories)) {
        throw new Error(
          'GitHub API returned an unexpected repository response.'
        );
      }

      allRepositories.push(...repositories);

      console.log(
        `Fetched page ${page}: ${repositories.length} repositories`
      );

      /**
       * If fewer than 100 repositories were returned,
       * we reached the final page.
       */
      if (repositories.length < perPage) {
        break;
      }

      page += 1;
    }

    const filteredRepositories = allRepositories.filter(
      (repo: any) => {
        if (HIDDEN_REPOSITORIES.has(repo.name)) {
          return false;
        }

        if (repo.fork) {
          return false;
        }

        return true;
      }
    );

    console.log(
      `GitHub returned ${allRepositories.length} repositories.`
    );

    console.log(
      `${filteredRepositories.length} repositories will appear on the Projects page.`
    );

    return filteredRepositories;
  } catch (error) {
    console.error(
      'GitHub repository synchronization failed:',
      error
    );

    /**
     * VERY IMPORTANT:
     *
     * Do NOT return [] here.
     *
     * Returning [] causes Astro to think that the user simply
     * has no repositories and can result in a broken Projects
     * page being deployed.
     *
     * Throwing the error causes the build to fail and therefore
     * prevents a bad build from replacing the last working site.
     */
    throw error;
  }
}

/**
 * Fetch a repository README.
 *
 * README failures are handled separately because a repository
 * can legitimately exist without a README.
 */
export async function getRepositoryReadme(
  repoName: string
): Promise<string | null> {
  try {
    const response = await githubFetch(
      `${GITHUB_API}/repos/${USERNAME}/${encodeURIComponent(
        repoName
      )}/readme`
    );

    const data = await response.json();

    if (!data?.content) {
      return null;
    }

    return Buffer.from(
      data.content,
      'base64'
    ).toString('utf-8');
  } catch (error) {
    /**
     * A missing README should not make the project page fail.
     */
    if (
      error instanceof Error &&
      error.message.includes('404')
    ) {
      return null;
    }

    console.error(
      `Error fetching README for ${repoName}:`,
      error
    );

    return null;
  }
}
