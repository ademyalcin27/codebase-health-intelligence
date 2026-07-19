import { z } from 'zod';
import fetch from 'node-fetch';

// Zod schema for validating project path input
const projectPathSchema = z.string().nonempty('Project path cannot be empty');

// Function to check known vulnerabilities using OSV.dev API
async function checkKnownVulnerabilities(projectPath: string) {
  // Validate the project path
  projectPathSchema.parse(projectPath);

  // Define the base URL for OSV.dev API
  const apiUrl = 'https://api.osv.dev/v1/query';

  // Fetch data from OSV.dev API
  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ path: projectPath }),
    });

    if (response.ok) {
      const data = await response.json();
      return data;
    } else {
      throw new Error(`Failed to fetch vulnerabilities: ${response.statusText}`);
    }
  } catch (error) {
    console.error('Error querying OSV.dev API:', error);
    return { error: 'Failed to fetch data from OSV.dev API' };
  }
}

export { checkKnownVulnerabilities, projectPathSchema };
