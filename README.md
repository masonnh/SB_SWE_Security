# Security Assignment for Sandbox SWE

## OWASP Category: Broken Access Control

**Real World Example:**
Snapchat fell victim to a breach due to broken access controls in their API, exposing 4.6 million usernames and phone numbers.
[Real more here.](https://qawerk.com/blog/broken-access-control/)

**Vulnerable NextJS Endpoint**
```typescript
import { NextApiRequest, NextApiResponse } from 'next'

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    const { id } = req.query
    
    // Vulnerable: No authentication check
    const userData = await prisma.user.findUnique({
        where: { id: String(id) },
        include: { 
            personalInfo: true,
            financialDetails: true 
        }
    })
    
    return res.json(userData)
}
```

**Steps to Patch Vulnerability**
1. Install and configure NextAuth.js for authentication
2. Add session validation to check if user is authenticated
3. Implement authorization check to verify user's access rights
4. Remove sensitive data fields from the response

**Fixed Version**
```typescript
import { NextApiRequest, NextApiResponse } from 'next'
import { getSession } from 'next-auth/react'

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    // Get user session
    const session = await getSession({ req })
    
    if (!session) {
        return res.status(401).json({ error: 'Unauthorized' })
    }
    
    const { id } = req.query
    
    // Verify user is accessing their own data
    if (session.user.id !== id) {
        return res.status(403).json({ error: 'Forbidden' })
    }
    
    const userData = await prisma.user.findUnique({
        where: { id: String(id) }
    })
    
    return res.json(userData)
}
```

**Prevention Tools & Processes**
- Implement NextAuth.js for authentication
- Use middleware to check authorization on all protected routes
- Regular security audits using tools like OWASP ZAP
- Implement role-based access control (RBAC)

## OWASP Category: Injection

**Real World Example:**
Hackers used SQL injection to steal 130 million credit card numbers from 7-Eleven.
[Read more here.](https://brightsec.com/blog/sql-injection-attack/)

**Vulnerable NextJS Endpoint**
```typescript
import { NextApiRequest, NextApiResponse } from 'next'
import { sql } from '@vercel/postgres'

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    const { searchTerm } = req.query
    
    // Vulnerable: Direct string interpolation
    const query = `
        SELECT * FROM products 
        WHERE name LIKE '%${searchTerm}%'
    `
    
    const results = await sql.query(query)
    return res.json(results)
}
```

**Steps to Patch Vulnerability**
1. Replace string interpolation with parameterized queries
2. Implement input validation and sanitization
3. Use an ORM like Prisma instead of raw SQL queries
4. Add type checking for all input parameters

**Fixed Version**
```typescript
import { NextApiRequest, NextApiResponse } from 'next'
import { sql } from '@vercel/postgres'

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    const { searchTerm } = req.query
    
    // Use parameterized queries
    const results = await sql.query(
        'SELECT * FROM products WHERE name LIKE $1',
        [`%${searchTerm}%`]
    )
    
    return res.json(results)
}
```

**Prevention Tools & Processes**
- Use ORM like Prisma with built-in SQL injection protection
- Input validation using libraries like Zod
- Regular security scanning with SQLMap

## OWASP Category: Server-Side Request Forgery (SSRF)

**Real World Example:**
Hackers exposed 100 million Capital One customer records by taking advantage of a SSRF vulnerability. They used a misconfigured WAF to send a request that ultimately gave them credentials to the WAF's compute instance.
[Read more here](https://brightsec.com/blog/ssrf-attack/)

**Vulnerable NextJS Endpoint**
```typescript
import { NextApiRequest, NextApiResponse } from 'next'
import fetch from 'node-fetch'

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    const { url } = req.query
    
    // Vulnerable: No URL validation
    const response = await fetch(url as string)
    const data = await response.text()
  
    return res.json({ data })
}
```

**Steps to Patch Vulnerability**
1. Implement URL parsing and validation
2. Create and enforce a whitelist of allowed domains
3. Add proper error handling for invalid URLs
4. Implement rate limiting for external requests
5. Set up logging for all external URL requests

**Fixed Version**
```typescript
import { NextApiRequest, NextApiResponse } from 'next'
import fetch from 'node-fetch'
import { URL } from 'url'

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    const { url } = req.query
  
    try {
        // Validate URL
        const parsedUrl = new URL(url as string)
        
        // Whitelist allowed domains
        const allowedDomains = ['api.trusted.com', 'api.safe.com']
        if (!allowedDomains.includes(parsedUrl.hostname)) {
            return res.status(403).json({ error: 'Domain not allowed' })
        }
    
        const response = await fetch(parsedUrl.toString())
        const data = await response.text()
        
        return res.json({ data })
    } catch (error) {
        return res.status(400).json({ error: 'Invalid URL' })
    }
}
```

**Prevention Tools & Processes**
- Implement URL validation middleware
- Use AWS IMDSv2 for metadata service access
- Network segmentation and firewall rules
- Regular penetration testing focusing on SSRF vectors
