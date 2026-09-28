/**
 * YSS Partners - Contact Form Submission Handler (Vercel Serverless Function)
 *
 * Implements:
 * - Server-side input validation and sanitization
 * - Multi-layer spam protection (honeypot, velocity timing, rate limiting)
 * - Category-based routing (Export & Import, IT Project and Risk, Partnership, General)
 * - Secure data handling (no credential leakage, safe fallback logging)
 */

// In-memory rate limiting map: IP -> array of timestamps
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = (parseInt(process.env.RATE_LIMIT_WINDOW_MINUTES, 10) || 10) * 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 5;

// Clean up stale rate-limiting entries periodically
function cleanupRateLimitMap() {
  const now = Date.now();
  for (const [ip, timestamps] of rateLimitMap.entries()) {
    const active = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (active.length === 0) {
      rateLimitMap.delete(ip);
    } else {
      rateLimitMap.set(ip, active);
    }
  }
}

// Allowed enquiry types matching approved specification
const ALLOWED_ENQUIRY_TYPES = [
  'Export & Import',
  'IT Project and Risk',
  'Partnership',
  'General',
];

// Strict email regex (RFC 5322 compatible subset)
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Mask email for safe logging (e.g. j***n@domain.com)
function maskEmail(email) {
  if (!email || typeof email !== 'string') return '***';
  const parts = email.split('@');
  if (parts.length !== 2) return '***';
  const user = parts[0];
  const domain = parts[1];
  const maskedUser = user.length <= 2 ? user[0] + '***' : user[0] + '***' + user[user.length - 1];
  return `${maskedUser}@${domain}`;
}

// Sanitize string to remove control characters
function sanitizeString(val) {
  if (typeof val !== 'string') return '';
  return val.replace(/[\u0000-\u001F\u007F-\u009F]/g, '').trim();
}

module.exports = async function handler(req, res) {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Type', 'application/json');

  // Allow preflight OPTIONS
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).json({ ok: true });
  }

  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed. Only POST requests are supported.',
    });
  }

  // 1. Rate Limiting Check
  const clientIp =
    (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null) ||
    req.socket?.remoteAddress ||
    '127.0.0.1';

  cleanupRateLimitMap();
  const now = Date.now();
  const timestamps = (rateLimitMap.get(clientIp) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

  if (timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      success: false,
      error: 'Too many enquiry submissions from this connection. Please wait a few minutes before submitting again.',
    });
  }
  timestamps.push(now);
  rateLimitMap.set(clientIp, timestamps);

  // 2. Parse Body
  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({
        success: false,
        error: 'Invalid request format. Expected JSON payload.',
      });
    }
  }
  body = body || {};

  // 3. Spam Honeypot Check
  // The honeypot field is hidden from legitimate users. If populated, silently accept as decoy.
  const honeypot = body._hp_company_url || body.website;
  if (honeypot && String(honeypot).trim().length > 0) {
    // Decoy success response: drops spam without alerting the bot
    return res.status(200).json({
      success: true,
      message: 'Thank you. Your enquiry has been received. We will review the details and contact you using the information provided.',
    });
  }

  // 4. Submission Velocity Check
  // Prevent instant automated bot submissions (less than 2.5 seconds from form load)
  const formRenderedAt = parseInt(body._form_rendered_at, 10);
  if (formRenderedAt) {
    const elapsedMs = now - formRenderedAt;
    if (elapsedMs < 2500) {
      // Form submitted unrealistically fast (bot behavior)
      return res.status(200).json({
        success: true,
        message: 'Thank you. Your enquiry has been received. We will review the details and contact you using the information provided.',
      });
    }
    // Token older than 24 hours
    if (elapsedMs > 24 * 60 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        error: 'Form session expired. Please refresh the page and submit again.',
      });
    }
  }

  // 5. Input Extraction and Sanitization
  const name = sanitizeString(body.name);
  const company = sanitizeString(body.company);
  const email = sanitizeString(body.email);
  const phone = sanitizeString(body.phone);
  const enquiryType = sanitizeString(body.enquiryType);
  const message = sanitizeString(body.message);
  const privacyConsent = body.privacyConsent === true || body.privacyConsent === 'true' || body.privacyConsent === 'on';

  // 6. Server-Side Validation
  const errors = [];

  // Name validation
  if (!name) {
    errors.push({ field: 'name', message: 'Full name is required.' });
  } else if (name.length < 2 || name.length > 100) {
    errors.push({ field: 'name', message: 'Name must be between 2 and 100 characters.' });
  }

  // Company validation (optional)
  if (company && company.length > 120) {
    errors.push({ field: 'company', message: 'Company name cannot exceed 120 characters.' });
  }

  // Email validation
  if (!email) {
    errors.push({ field: 'email', message: 'Business email is required.' });
  } else if (email.length > 150) {
    errors.push({ field: 'email', message: 'Email address cannot exceed 150 characters.' });
  } else if (!EMAIL_REGEX.test(email)) {
    errors.push({ field: 'email', message: 'Please provide a valid email address.' });
  }

  // Phone validation (optional)
  if (phone) {
    if (phone.length > 50) {
      errors.push({ field: 'phone', message: 'Phone number cannot exceed 50 characters.' });
    } else if (!/^[\d\s+\-().]+$/.test(phone)) {
      errors.push({ field: 'phone', message: 'Phone number contains invalid characters.' });
    }
  }

  // Enquiry Type validation
  if (!enquiryType) {
    errors.push({ field: 'enquiryType', message: 'Please select an enquiry type.' });
  } else if (!ALLOWED_ENQUIRY_TYPES.includes(enquiryType)) {
    errors.push({ field: 'enquiryType', message: 'Selected enquiry type is not valid.' });
  }

  // Message validation
  if (!message) {
    errors.push({ field: 'message', message: 'Message outline is required.' });
  } else if (message.length < 10) {
    errors.push({ field: 'message', message: 'Please provide a concise outline of at least 10 characters.' });
  } else if (message.length > 3000) {
    errors.push({ field: 'message', message: 'Message outline cannot exceed 3,000 characters.' });
  }

  // Privacy acknowledgement validation
  if (!privacyConsent) {
    errors.push({ field: 'privacyConsent', message: 'You must consent to YSS Partners using the submitted details to respond to your enquiry.' });
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      error: 'Please correct the indicated fields and try again.',
      details: errors,
    });
  }

  // 7. Category-Based Routing
  let destinationEmail = process.env.CONTACT_EMAIL_TO || 'enquiries@ysspartners.com';

  switch (enquiryType) {
    case 'Export & Import':
      destinationEmail = process.env.EXPORT_IMPORT_EMAIL || destinationEmail;
      break;
    case 'IT Project and Risk':
      destinationEmail = process.env.IT_RISK_EMAIL || destinationEmail;
      break;
    case 'Partnership':
      destinationEmail = process.env.PARTNERSHIP_EMAIL || destinationEmail;
      break;
    case 'General':
      destinationEmail = process.env.GENERAL_EMAIL || destinationEmail;
      break;
  }

  // 8. Email Dispatch / Notification Handler
  const senderEmail = process.env.CONTACT_EMAIL_FROM || 'notifications@ysspartners.com';
  const resendApiKey = process.env.RESEND_API_KEY;

  if (resendApiKey) {
    try {
      const emailPayload = {
        from: senderEmail,
        to: [destinationEmail],
        reply_to: email,
        subject: `[YSS Enquiry - ${enquiryType}] From ${name}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; color: #17172b; line-height: 1.6;">
            <div style="background: #0b0b67; padding: 20px; color: #ffffff; border-radius: 8px 8px 0 0;">
              <h2 style="margin: 0; font-size: 20px;">YSS Partners - New Qualified Enquiry</h2>
              <p style="margin: 5px 0 0; color: #ffd866; font-size: 13px;">Category: ${escapeHtml(enquiryType)}</p>
            </div>
            <div style="border: 1px solid #e7e8ef; border-top: none; padding: 24px; border-radius: 0 0 8px 8px;">
              <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px 0; color: #6f7282; width: 140px;"><strong>Full Name:</strong></td><td>${escapeHtml(name)}</td></tr>
                <tr><td style="padding: 8px 0; color: #6f7282;"><strong>Company:</strong></td><td>${escapeHtml(company || '—')}</td></tr>
                <tr><td style="padding: 8px 0; color: #6f7282;"><strong>Email:</strong></td><td><a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></td></tr>
                <tr><td style="padding: 8px 0; color: #6f7282;"><strong>Phone / WhatsApp:</strong></td><td>${escapeHtml(phone || '—')}</td></tr>
                <tr><td style="padding: 8px 0; color: #6f7282;"><strong>Enquiry Type:</strong></td><td><span style="background: #fff8df; color: #6d5a12; padding: 3px 8px; border-radius: 4px; font-weight: bold;">${escapeHtml(enquiryType)}</span></td></tr>
                <tr><td style="padding: 8px 0; color: #6f7282;"><strong>Privacy Consent:</strong></td><td>Confirmed</td></tr>
              </table>
              <div style="margin-top: 20px; padding-top: 16px; border-top: 1px solid #e7e8ef;">
                <strong style="display: block; margin-bottom: 8px; color: #0b0b67;">Message Outline:</strong>
                <div style="white-space: pre-wrap; background: #f6f7fb; padding: 14px; border-radius: 6px; font-size: 14px; color: #17172b;">${escapeHtml(message)}</div>
              </div>
            </div>
          </div>
        `,
      };

      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${resendApiKey}`,
        },
        body: JSON.stringify(emailPayload),
      });

      if (!response.ok) {
        // Log non-sensitive failure metadata
        console.error(`[Email Dispatch Error] Status: ${response.status} for category ${enquiryType}`);
      }
    } catch (err) {
      console.error('[Email Dispatch Exception] An error occurred during email transmission');
    }
  } else {
    // Staging / Unconfigured provider fallback: Log safe audit notice
    // Note: Do not print raw message content or confidential values in production logs
    console.log(
      JSON.stringify({
        event: 'ENQUIRY_RECEIVED',
        timestamp: new Date().toISOString(),
        category: enquiryType,
        senderMasked: maskEmail(email),
        routedTo: destinationEmail,
        providerConfigured: false,
      })
    );
  }

  // 9. Client Success Response
  return res.status(200).json({
    success: true,
    message: 'Thank you. Your enquiry has been received. We will review the details and contact you using the information provided.',
  });
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
