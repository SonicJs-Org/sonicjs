import type { D1Database } from '@cloudflare/workers-types'

export interface SeedOptions {
  userCount: number
  contentCount: number
  formCount: number
  submissionsPerForm: number
  richness: 'minimal' | 'full'
}

export interface SeedResult {
  users: number
  content: number
  forms: number
  submissions: number
}

export class SeedDataService {
  constructor(private db: D1Database) {}

  // ============================================================================
  // Data Arrays
  // ============================================================================

  private firstNames = [
    'Emma', 'Liam', 'Olivia', 'Noah', 'Ava', 'Ethan', 'Sophia', 'Mason',
    'Isabella', 'William', 'Mia', 'James', 'Charlotte', 'Benjamin', 'Amelia',
    'Lucas', 'Harper', 'Henry', 'Evelyn', 'Alexander', 'Aria', 'Daniel',
    'Chloe', 'Michael', 'Penelope', 'Sebastian', 'Layla', 'Jack', 'Riley', 'Owen'
  ]

  private lastNames = [
    'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
    'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson',
    'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson',
    'White', 'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson'
  ]

  private blogTitles = [
    'Getting Started with Modern Web Development',
    'The Future of JavaScript Frameworks',
    'Building Scalable Applications with Microservices',
    'Understanding TypeScript: A Complete Guide',
    'Best Practices for API Design',
    'Introduction to Cloud Computing',
    'Mastering Git and Version Control',
    'The Art of Code Review',
    'Performance Optimization Techniques',
    'Security Best Practices for Web Apps',
    'Exploring Serverless Architecture',
    'Database Design Fundamentals',
    'Testing Strategies for Modern Apps',
    'CI/CD Pipeline Implementation',
    'Mobile-First Development Approach',
    'GraphQL vs REST: A Practical Comparison',
    'Building Real-Time Applications with WebSockets',
    'Container Orchestration with Kubernetes',
    'Edge Computing and the Modern Web',
    'Accessibility in Web Development'
  ]

  private pageTitles = [
    'About Us', 'Contact', 'Privacy Policy', 'Terms of Service',
    'FAQ', 'Our Team', 'Careers', 'Press Kit',
    'Support', 'Documentation', 'Pricing', 'Features'
  ]

  private productTitles = [
    'Premium Wireless Headphones', 'Smart Watch Pro', 'Laptop Stand Adjustable',
    'Mechanical Keyboard RGB', 'HD Webcam 4K', 'USB-C Hub 7-in-1',
    'Portable SSD 1TB', 'Wireless Mouse Ergonomic', 'Monitor 27" 4K',
    'Desk Lamp LED', 'Phone Case Premium', 'Tablet Stand Aluminum',
    'Cable Management Kit', 'Power Bank 20000mAh', 'Bluetooth Speaker Portable'
  ]

  private blogParagraphs = [
    'Modern web development has evolved significantly over the past decade. What once required extensive server-side rendering and page reloads now leverages sophisticated client-side frameworks and APIs. The shift toward component-based architectures has fundamentally changed how we think about building user interfaces.',
    'Performance optimization remains one of the most critical aspects of web application development. Users expect pages to load in under two seconds, and search engines increasingly factor page speed into their ranking algorithms. Techniques like code splitting, lazy loading, and edge caching have become essential tools in every developer\'s toolkit.',
    'Security should never be an afterthought in software development. From input validation and output encoding to proper authentication and authorization, every layer of your application needs careful consideration. The OWASP Top 10 provides an excellent starting point for understanding the most common security vulnerabilities.',
    'Testing is the backbone of reliable software delivery. A well-balanced test pyramid with unit tests at the base, integration tests in the middle, and end-to-end tests at the top ensures comprehensive coverage without sacrificing speed. Automated testing in CI/CD pipelines catches regressions before they reach production.',
    'The rise of serverless computing has transformed how we deploy and scale applications. By abstracting away infrastructure management, developers can focus entirely on business logic. Functions-as-a-Service platforms like Cloudflare Workers offer millisecond cold starts and global distribution out of the box.',
    'TypeScript has become the de facto standard for large-scale JavaScript applications. Its static type system catches errors at compile time, provides excellent IDE support with autocompletion and refactoring tools, and makes codebases significantly more maintainable as teams and projects grow.',
    'API design is both an art and a science. RESTful APIs should follow consistent naming conventions, use appropriate HTTP methods, and return meaningful status codes. GraphQL offers an alternative approach with its query language, allowing clients to request exactly the data they need.',
    'DevOps practices bridge the gap between development and operations teams. Continuous integration ensures code changes are tested automatically, while continuous deployment streamlines the release process. Infrastructure as code allows teams to version control their entire deployment environment.',
    'Microservices architecture enables teams to develop, deploy, and scale individual components independently. Each service owns its data and communicates through well-defined APIs. However, this approach introduces complexity in areas like service discovery, distributed tracing, and eventual consistency.',
    'Edge computing brings computation closer to the end user, dramatically reducing latency for global applications. Content delivery networks have evolved beyond static asset caching to support full application logic at the edge. This paradigm shift enables new categories of real-time, location-aware applications.',
    'Accessible web applications are not optional — they are a fundamental requirement. Screen readers, keyboard navigation, and proper semantic HTML ensure that everyone can use your application. WCAG guidelines provide clear standards for achieving accessibility compliance across your entire product.',
    'Database design decisions have lasting impacts on application performance and scalability. Choosing between SQL and NoSQL databases depends on your data relationships, query patterns, and consistency requirements. Proper indexing, query optimization, and connection pooling are critical regardless of your database choice.',
    'Version control with Git is more than just tracking changes. Branching strategies like GitFlow and trunk-based development define how teams collaborate on features, fixes, and releases. Understanding rebasing, cherry-picking, and conflict resolution makes you a more effective team member.',
    'Progressive Web Apps combine the best of web and native applications. Service workers enable offline functionality, push notifications keep users engaged, and the app manifest provides an installable experience. PWAs offer near-native performance without the overhead of app store distribution.',
    'Monitoring and observability are essential for maintaining production applications. Structured logging, distributed tracing, and metrics dashboards help teams identify and resolve issues quickly. Alert fatigue is real — focus on actionable alerts that indicate genuine problems requiring human intervention.',
    'Code review is one of the most valuable practices in software development. Beyond catching bugs, it promotes knowledge sharing, maintains code quality standards, and helps junior developers grow. Effective reviews focus on architecture, logic, and maintainability rather than style preferences.',
    'Container technology has revolutionized application deployment. Docker containers package applications with their dependencies, ensuring consistency across development, testing, and production environments. Multi-stage builds optimize image sizes while maintaining a clean development workflow.',
    'State management in complex applications requires careful architectural decisions. Whether using Redux, MobX, Zustand, or built-in framework solutions, the key is choosing the right level of complexity for your needs. Over-engineering state management leads to boilerplate; under-engineering leads to spaghetti code.',
    'Internationalization and localization go beyond simple text translation. Date formats, number formatting, right-to-left layouts, and cultural considerations all play a role in creating truly global applications. Planning for i18n from the start is far easier than retrofitting it later.',
    'The JAMstack architecture has gained tremendous popularity for content-driven websites. Pre-rendered pages served from CDNs provide excellent performance, while APIs handle dynamic functionality. Static site generators and headless CMS platforms make this architecture accessible to teams of all sizes.'
  ]

  private blogExcerpts = [
    'A comprehensive guide covering essential concepts and practical techniques for modern development.',
    'Explore the latest trends shaping the future of web applications and software engineering.',
    'Practical tips and real-world examples to improve your development workflow and productivity.',
    'Deep dive into advanced concepts with step-by-step instructions for developers of all levels.',
    'Learn proven strategies and best practices used by industry-leading engineering teams.',
    'Master the essential skills and tools needed to build production-ready applications.',
    'An in-depth look at architectures, patterns, and methodologies for scalable software.',
    'Discover cutting-edge techniques that will transform how you approach software development.',
    'From fundamentals to advanced topics — everything you need to level up your skills.',
    'Expert insights and actionable advice for building robust, maintainable applications.',
    'Understanding the core principles that separate great software from merely functional code.',
    'A practical walkthrough with code examples, diagrams, and real-world case studies.',
    'Lessons learned from production systems serving millions of users worldwide.',
    'Navigate common pitfalls and make informed decisions about your technology stack.',
    'Bridge the gap between theory and practice with hands-on examples and exercises.'
  ]

  private allTags = [
    'tutorial', 'guide', 'javascript', 'typescript', 'web-dev', 'backend', 'frontend',
    'best-practices', 'security', 'performance', 'testing', 'deployment', 'cloud',
    'database', 'api', 'react', 'vue', 'nextjs', 'serverless', 'edge-computing',
    'graphql', 'rest-api', 'devops', 'ci-cd', 'docker', 'kubernetes', 'monitoring',
    'accessibility', 'seo', 'ux-design'
  ]

  private pageContentTemplates: Record<string, string> = {
    'About Us': '<h2>Our Story</h2><p>Founded with a vision to simplify content management, our team has been building innovative solutions for businesses of all sizes. We believe that powerful technology should be accessible to everyone, not just large enterprises with dedicated engineering teams.</p><h2>Our Mission</h2><p>We are committed to providing the most developer-friendly, performant, and flexible content management platform available. Our open-source approach ensures transparency and community-driven innovation.</p><p>With users across 40+ countries and thousands of active installations, we continue to push the boundaries of what a modern CMS can achieve.</p>',
    'Contact': '<h2>Get in Touch</h2><p>We would love to hear from you. Whether you have a question about our platform, need technical support, or want to explore partnership opportunities, our team is ready to help.</p><p><strong>Email:</strong> hello@example.com<br/><strong>Phone:</strong> (555) 123-4567<br/><strong>Address:</strong> 123 Innovation Drive, Suite 400, San Francisco, CA 94105</p><h2>Office Hours</h2><p>Monday through Friday, 9:00 AM to 6:00 PM Pacific Time. We typically respond to inquiries within 24 business hours.</p>',
    'Privacy Policy': '<h2>Privacy Policy</h2><p>Last updated: January 2026. This Privacy Policy describes how we collect, use, and protect your personal information when you use our services.</p><h2>Information We Collect</h2><p>We collect information you provide directly, such as when you create an account, submit a form, or contact us. We also collect certain information automatically, including usage data, IP addresses, and browser information.</p><h2>How We Use Your Information</h2><p>We use the information we collect to provide and improve our services, communicate with you, and ensure the security of our platform. We do not sell your personal information to third parties.</p><h2>Data Retention</h2><p>We retain your information for as long as your account is active or as needed to provide you with our services. You may request deletion of your data at any time by contacting our support team.</p>',
    'Terms of Service': '<h2>Terms of Service</h2><p>By accessing and using this platform, you agree to be bound by these Terms of Service. Please read them carefully before using our services.</p><h2>Account Responsibilities</h2><p>You are responsible for maintaining the confidentiality of your account credentials and for all activities that occur under your account. You agree to notify us immediately of any unauthorized use.</p><h2>Acceptable Use</h2><p>You agree to use our services only for lawful purposes and in accordance with these Terms. You may not use our platform to distribute harmful content, violate intellectual property rights, or engage in any activity that disrupts our services.</p><h2>Limitation of Liability</h2><p>Our platform is provided "as is" without warranties of any kind. We shall not be liable for any indirect, incidental, or consequential damages arising from your use of our services.</p>',
    'FAQ': '<h2>Frequently Asked Questions</h2><h3>What is this platform?</h3><p>Our platform is a modern, headless content management system built for speed, flexibility, and developer experience. It runs on edge infrastructure for global performance.</p><h3>How do I get started?</h3><p>Simply create an account, define your content collections, and start creating content. Our API-first approach means you can integrate with any frontend framework or static site generator.</p><h3>Is there a free tier?</h3><p>Yes, our free tier includes everything you need to get started, including API access, basic search, and community support. Upgrade to Pro for advanced features like AI search and custom workflows.</p><h3>Can I migrate from another CMS?</h3><p>Absolutely. We provide migration tools and guides for popular platforms including WordPress, Strapi, Contentful, and Sanity. Our support team can assist with complex migrations.</p>',
    'Our Team': '<h2>Meet Our Team</h2><p>We are a diverse team of engineers, designers, and product thinkers passionate about building the future of content management.</p><h3>Leadership</h3><p>Our leadership team brings decades of combined experience from companies like Google, AWS, Cloudflare, and Vercel. We are united by a shared belief that content infrastructure should be fast, reliable, and enjoyable to work with.</p><h3>Engineering</h3><p>Our engineering team specializes in edge computing, distributed systems, and developer experience. We build with TypeScript, Cloudflare Workers, and modern web standards.</p><h3>Join Us</h3><p>We are always looking for talented individuals who share our passion. Check our careers page for current openings.</p>',
    'Careers': '<h2>Join Our Team</h2><p>We are building the future of content management and we need talented people to help us get there. We offer competitive compensation, remote-first culture, and the opportunity to work on technology used by thousands of developers worldwide.</p><h2>Open Positions</h2><p><strong>Senior Full-Stack Engineer</strong> — Work on our core platform, building features that scale to millions of requests. TypeScript, Cloudflare Workers, and distributed systems experience preferred.</p><p><strong>Developer Advocate</strong> — Help developers succeed with our platform through documentation, tutorials, talks, and community engagement.</p><p><strong>Product Designer</strong> — Design intuitive admin interfaces and developer experiences that make complex tasks simple.</p>',
    'Pricing': '<h2>Simple, Transparent Pricing</h2><p>Choose the plan that fits your needs. All plans include our core features with no hidden fees.</p><h3>Free</h3><p>Perfect for personal projects and getting started. Includes 1,000 API requests/day, 3 collections, and community support.</p><h3>Pro — $29/month</h3><p>For growing teams and production applications. Includes unlimited API requests, unlimited collections, AI-powered search, priority support, and custom domains.</p><h3>Enterprise — Custom</h3><p>For organizations with advanced requirements. Includes dedicated infrastructure, SLA guarantees, SSO/SAML, audit logs, and a dedicated account manager. Contact us for a quote.</p>',
    'Features': '<h2>Powerful Features for Modern Content</h2><h3>Headless API</h3><p>RESTful API with full CRUD operations, filtering, sorting, and pagination. Query your content from any frontend or service.</p><h3>AI-Powered Search</h3><p>Full-text search with BM25 ranking, semantic search with vector embeddings, and hybrid mode that combines both for best results.</p><h3>Form Builder</h3><p>Drag-and-drop form builder with 20+ field types, validation rules, and submission management. Embed forms anywhere with our JavaScript SDK.</p><h3>Edge Performance</h3><p>Built on Cloudflare Workers for sub-50ms response times globally. Your content is served from 300+ data centers worldwide.</p>',
    'Support': '<h2>How Can We Help?</h2><p>Our support team is here to ensure your success with the platform. Choose the support channel that works best for you.</p><h3>Documentation</h3><p>Comprehensive guides, API references, and tutorials covering every aspect of the platform. Start with our quickstart guide to get up and running in minutes.</p><h3>Community</h3><p>Join our Discord community to connect with other developers, share tips, and get help from the community. Our team is active in the community channels daily.</p><h3>Email Support</h3><p>For technical issues and account questions, email support@example.com. Pro and Enterprise customers receive priority response times.</p>',
    'Documentation': '<h2>Getting Started</h2><p>Welcome to the documentation. This guide will help you understand the platform architecture, set up your development environment, and build your first application.</p><h3>Quick Start</h3><p>1. Install the CLI tool with npm. 2. Initialize a new project. 3. Define your collections. 4. Start the development server. 5. Create content via the admin UI or API.</p><h3>API Reference</h3><p>Our REST API follows standard conventions with JSON request/response bodies. Authentication uses JWT tokens. All endpoints support filtering, sorting, and pagination.</p><h3>Deployment</h3><p>Deploy to Cloudflare Workers with a single command. Configure custom domains, environment variables, and D1 database bindings in your wrangler.toml file.</p>'
  }

  private productDescriptions: Record<string, string> = {
    'Premium Wireless Headphones': 'Experience crystal-clear audio with our Premium Wireless Headphones. Featuring active noise cancellation with three adjustable levels, 40mm custom-tuned drivers, and up to 30 hours of battery life on a single charge. The memory foam ear cushions provide all-day comfort while the foldable design makes them perfect for travel. Supports Bluetooth 5.2 with multipoint connection for seamless switching between devices.',
    'Smart Watch Pro': 'Stay connected and track your health with the Smart Watch Pro. Features a vibrant 1.4" AMOLED display, continuous heart rate monitoring, blood oxygen sensing, and sleep tracking. Water-resistant to 50 meters with GPS for outdoor activities. Receive notifications, control music, and pay contactlessly — all from your wrist. Battery lasts up to 7 days with typical use.',
    'Laptop Stand Adjustable': 'Elevate your workspace ergonomics with our adjustable laptop stand. CNC-machined from a single piece of aluminum alloy for maximum stability and heat dissipation. Adjusts from 6" to 12" in height with 360-degree rotation. Compatible with laptops from 10" to 17". Non-slip silicone pads protect your device. Weighs just 1.2 lbs and folds flat for portability.',
    'Mechanical Keyboard RGB': 'Type with precision on our mechanical keyboard featuring hot-swappable switches, per-key RGB backlighting with 16.8 million colors, and programmable macros. Durable PBT double-shot keycaps will not fade over time. N-key rollover ensures every keystroke is registered during intense gaming sessions. Detachable USB-C cable and compact 75% layout save desk space.',
    'HD Webcam 4K': 'Look your best on every video call with our 4K Ultra HD webcam. Sony STARVIS sensor delivers stunning clarity even in low light conditions. Built-in noise-canceling dual microphones pick up your voice clearly while reducing background noise. Auto-framing AI keeps you centered as you move. Privacy shutter for peace of mind when not in use.',
    'USB-C Hub 7-in-1': 'Expand your laptop\'s connectivity with our 7-in-1 USB-C hub. Includes 4K HDMI output at 60Hz, two USB 3.0 ports, SD and microSD card readers, USB-C power delivery pass-through up to 100W, and Gigabit Ethernet. Compact aluminum design with braided cable. Compatible with MacBook, Dell XPS, ThinkPad, and all USB-C laptops.',
    'Portable SSD 1TB': 'Lightning-fast storage you can take anywhere. Sequential read speeds up to 1,050 MB/s and write speeds up to 1,000 MB/s over USB 3.2 Gen 2. Rugged design survives drops up to 6 feet. Hardware AES 256-bit encryption protects your data. Compatible with PC, Mac, PlayStation, and Xbox. Compact form factor weighs only 1.8 oz.',
    'Wireless Mouse Ergonomic': 'Say goodbye to wrist strain with our ergonomically designed wireless mouse. The 57-degree vertical angle promotes a natural handshake position. Precision 4000 DPI optical sensor works on virtually any surface. Connects via Bluetooth or included USB receiver. Quiet click buttons and textured thumb rest. Single AA battery lasts up to 18 months.',
    'Monitor 27" 4K': 'Immerse yourself in stunning detail with our 27-inch 4K UHD monitor. IPS panel delivers 100% sRGB and 95% DCI-P3 color accuracy. Factory calibrated to Delta E < 2 for professional color work. USB-C connectivity with 65W power delivery charges your laptop while displaying at full resolution. Adjustable stand with height, tilt, swivel, and pivot. Built-in KVM switch for dual-computer setups.',
    'Desk Lamp LED': 'Illuminate your workspace with our award-winning LED desk lamp. Stepless brightness and color temperature adjustment from warm 2700K to cool 6500K. CRI > 95 for accurate color rendering. Built-in ambient light sensor automatically adjusts to your environment. USB charging port on the base. Memory function remembers your preferred settings. Energy Star certified.',
    'Phone Case Premium': 'Military-grade protection meets premium design. Our phone case features a triple-layer construction with shock-absorbing TPU, rigid polycarbonate shell, and soft microfiber lining. Tested to survive 10-foot drops on concrete. Raised bezels protect the camera and screen. MagSafe compatible for wireless charging. Available in 6 colors with a lifetime warranty.',
    'Tablet Stand Aluminum': 'The perfect companion for your tablet or iPad. Precision-engineered aluminum construction with a weighted base prevents tipping. Adjustable viewing angle from 0 to 135 degrees. Rubber padding protects your device and prevents slipping. Cable routing channel keeps your workspace tidy. Compatible with all tablets from 7" to 13". Ideal for drawing, video calls, and recipe following.',
    'Cable Management Kit': 'Tame your cable chaos with our comprehensive cable management kit. Includes 10 reusable silicone cable ties, 6 adhesive cable clips, 2 under-desk cable trays, 1 cable sleeve (6 ft), and 20 cable labels. All components are tool-free installation. The under-desk trays hold up to 10 cables each and include power strip mounts. Everything you need for a clean, organized workspace.',
    'Power Bank 20000mAh': 'Never run out of power on the go. Our 20,000mAh power bank charges an iPhone up to 5 times or a MacBook Air once. Dual USB-C ports support 65W PD fast charging — recharge the power bank itself in just 2 hours. LED display shows exact remaining capacity. Pass-through charging lets you charge devices while recharging the bank. Airline approved for carry-on luggage.',
    'Bluetooth Speaker Portable': 'Rich, room-filling sound in a compact package. Dual 10W drivers and passive bass radiator deliver surprisingly deep bass. IP67 waterproof and dustproof — take it to the beach, pool, or shower. 24-hour battery life with USB-C fast charging (15 minutes = 3 hours of playback). Pair two speakers for true stereo sound. Built-in microphone for hands-free calls.'
  }

  private productCategories = ['Electronics', 'Accessories', 'Peripherals', 'Storage', 'Audio']

  // ============================================================================
  // Form Templates
  // ============================================================================

  private formTemplates = [
    {
      name: 'contact_us',
      display_name: 'Contact Us',
      description: 'General contact form for inquiries and messages',
      category: 'contact',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'name', label: 'Full Name', placeholder: 'Enter your full name', validate: { required: true, maxLength: 100 } },
          { type: 'email', key: 'email', label: 'Email Address', placeholder: 'you@example.com', validate: { required: true } },
          { type: 'phoneNumber', key: 'phone', label: 'Phone Number', placeholder: '(555) 123-4567' },
          { type: 'select', key: 'subject', label: 'Subject', data: { values: [
            { label: 'General Inquiry', value: 'general' },
            { label: 'Technical Support', value: 'support' },
            { label: 'Sales', value: 'sales' },
            { label: 'Partnership', value: 'partnership' },
            { label: 'Press/Media', value: 'press' }
          ] }, validate: { required: true } },
          { type: 'textarea', key: 'message', label: 'Message', placeholder: 'How can we help you?', validate: { required: true, maxLength: 2000 } }
        ]
      },
      settings: { emailNotifications: true, notifyEmail: 'admin@example.com', successMessage: 'Thank you for reaching out! We will get back to you within 24 hours.', submitButtonText: 'Send Message', requireAuth: false }
    },
    {
      name: 'customer_feedback',
      display_name: 'Customer Feedback',
      description: 'Collect customer feedback and satisfaction ratings',
      category: 'feedback',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'name', label: 'Your Name', placeholder: 'Enter your name' },
          { type: 'email', key: 'email', label: 'Email', validate: { required: true } },
          { type: 'radio', key: 'satisfaction', label: 'Overall Satisfaction', values: [
            { label: 'Very Satisfied', value: '5' }, { label: 'Satisfied', value: '4' },
            { label: 'Neutral', value: '3' }, { label: 'Dissatisfied', value: '2' },
            { label: 'Very Dissatisfied', value: '1' }
          ], validate: { required: true } },
          { type: 'selectboxes', key: 'improvements', label: 'What areas can we improve?', values: [
            { label: 'Product Quality', value: 'quality' }, { label: 'Customer Service', value: 'service' },
            { label: 'Pricing', value: 'pricing' }, { label: 'Website Experience', value: 'website' },
            { label: 'Documentation', value: 'docs' }, { label: 'Delivery Speed', value: 'delivery' }
          ] },
          { type: 'textarea', key: 'comments', label: 'Additional Comments', placeholder: 'Tell us more about your experience...' }
        ]
      },
      settings: { successMessage: 'Thank you for your feedback! We appreciate you taking the time.', submitButtonText: 'Submit Feedback', requireAuth: false }
    },
    {
      name: 'event_registration',
      display_name: 'Event Registration',
      description: 'Register for upcoming events and workshops',
      category: 'registration',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'firstName', label: 'First Name', validate: { required: true } },
          { type: 'textfield', key: 'lastName', label: 'Last Name', validate: { required: true } },
          { type: 'email', key: 'email', label: 'Email', validate: { required: true } },
          { type: 'phoneNumber', key: 'phone', label: 'Phone Number' },
          { type: 'textfield', key: 'company', label: 'Company / Organization' },
          { type: 'select', key: 'eventType', label: 'Event', data: { values: [
            { label: 'Annual Conference 2026', value: 'conference-2026' },
            { label: 'Web Development Workshop', value: 'webdev-workshop' },
            { label: 'Product Launch Webinar', value: 'product-launch' },
            { label: 'Community Meetup', value: 'meetup' }
          ] }, validate: { required: true } },
          { type: 'select', key: 'dietary', label: 'Dietary Restrictions', data: { values: [
            { label: 'None', value: 'none' }, { label: 'Vegetarian', value: 'vegetarian' },
            { label: 'Vegan', value: 'vegan' }, { label: 'Gluten-Free', value: 'gluten-free' },
            { label: 'Kosher', value: 'kosher' }, { label: 'Halal', value: 'halal' }
          ] } },
          { type: 'checkbox', key: 'agreeTerms', label: 'I agree to the terms and conditions', validate: { required: true } }
        ]
      },
      settings: { successMessage: 'You are registered! Check your email for confirmation details.', submitButtonText: 'Register', requireAuth: false }
    },
    {
      name: 'customer_survey',
      display_name: 'Customer Survey',
      description: 'Comprehensive customer satisfaction survey',
      category: 'survey',
      formio_schema: {
        components: [
          { type: 'email', key: 'email', label: 'Email (optional)' },
          { type: 'radio', key: 'productRating', label: 'How would you rate our product?', values: [
            { label: 'Excellent', value: '5' }, { label: 'Good', value: '4' },
            { label: 'Average', value: '3' }, { label: 'Below Average', value: '2' },
            { label: 'Poor', value: '1' }
          ], validate: { required: true } },
          { type: 'radio', key: 'supportRating', label: 'How would you rate our support?', values: [
            { label: 'Excellent', value: '5' }, { label: 'Good', value: '4' },
            { label: 'Average', value: '3' }, { label: 'Below Average', value: '2' },
            { label: 'Poor', value: '1' }
          ], validate: { required: true } },
          { type: 'radio', key: 'recommend', label: 'Would you recommend us to others?', values: [
            { label: 'Definitely', value: 'definitely' }, { label: 'Probably', value: 'probably' },
            { label: 'Not Sure', value: 'not-sure' }, { label: 'Probably Not', value: 'probably-not' },
            { label: 'Definitely Not', value: 'definitely-not' }
          ], validate: { required: true } },
          { type: 'textarea', key: 'feedback', label: 'What could we do better?', placeholder: 'Your honest feedback helps us improve...' }
        ]
      },
      settings: { successMessage: 'Thank you for completing our survey!', submitButtonText: 'Submit Survey', requireAuth: false }
    },
    {
      name: 'newsletter_signup',
      display_name: 'Newsletter Signup',
      description: 'Subscribe to our newsletter for updates and news',
      category: 'general',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'name', label: 'Name', placeholder: 'Your name', validate: { required: true } },
          { type: 'email', key: 'email', label: 'Email Address', validate: { required: true } },
          { type: 'select', key: 'frequency', label: 'Preferred Frequency', data: { values: [
            { label: 'Weekly Digest', value: 'weekly' },
            { label: 'Bi-Weekly', value: 'biweekly' },
            { label: 'Monthly Summary', value: 'monthly' }
          ] } },
          { type: 'selectboxes', key: 'interests', label: 'Topics of Interest', values: [
            { label: 'Product Updates', value: 'products' }, { label: 'Engineering Blog', value: 'engineering' },
            { label: 'Industry News', value: 'news' }, { label: 'Tips & Tutorials', value: 'tutorials' },
            { label: 'Events & Webinars', value: 'events' }
          ] }
        ]
      },
      settings: { successMessage: 'Welcome aboard! Check your inbox to confirm your subscription.', submitButtonText: 'Subscribe', requireAuth: false }
    },
    {
      name: 'support_ticket',
      display_name: 'Support Ticket',
      description: 'Submit a technical support request',
      category: 'contact',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'name', label: 'Your Name', validate: { required: true } },
          { type: 'email', key: 'email', label: 'Email', validate: { required: true } },
          { type: 'select', key: 'priority', label: 'Priority', data: { values: [
            { label: 'Low — General question', value: 'low' },
            { label: 'Medium — Issue affecting workflow', value: 'medium' },
            { label: 'High — Service degraded', value: 'high' },
            { label: 'Critical — Service down', value: 'critical' }
          ] }, validate: { required: true } },
          { type: 'select', key: 'category', label: 'Category', data: { values: [
            { label: 'Account & Billing', value: 'billing' },
            { label: 'API & Integration', value: 'api' },
            { label: 'Performance', value: 'performance' },
            { label: 'Bug Report', value: 'bug' },
            { label: 'Feature Request', value: 'feature' }
          ] }, validate: { required: true } },
          { type: 'textarea', key: 'description', label: 'Description', placeholder: 'Describe the issue in detail...', validate: { required: true, maxLength: 5000 } },
          { type: 'url', key: 'url', label: 'Related URL (optional)', placeholder: 'https://' }
        ]
      },
      settings: { emailNotifications: true, notifyEmail: 'support@example.com', successMessage: 'Your support ticket has been submitted. We will respond within 4 business hours.', submitButtonText: 'Submit Ticket', requireAuth: false }
    },
    {
      name: 'job_application',
      display_name: 'Job Application',
      description: 'Apply for open positions at our company',
      category: 'registration',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'firstName', label: 'First Name', validate: { required: true } },
          { type: 'textfield', key: 'lastName', label: 'Last Name', validate: { required: true } },
          { type: 'email', key: 'email', label: 'Email', validate: { required: true } },
          { type: 'phoneNumber', key: 'phone', label: 'Phone Number', validate: { required: true } },
          { type: 'url', key: 'portfolio', label: 'Portfolio / LinkedIn URL', placeholder: 'https://' },
          { type: 'select', key: 'position', label: 'Position', data: { values: [
            { label: 'Senior Full-Stack Engineer', value: 'senior-fullstack' },
            { label: 'Frontend Developer', value: 'frontend' },
            { label: 'Backend Engineer', value: 'backend' },
            { label: 'DevOps Engineer', value: 'devops' },
            { label: 'Product Designer', value: 'designer' },
            { label: 'Developer Advocate', value: 'devrel' }
          ] }, validate: { required: true } },
          { type: 'textarea', key: 'coverLetter', label: 'Cover Letter', placeholder: 'Tell us why you are interested in this role...', validate: { required: true, maxLength: 3000 } }
        ]
      },
      settings: { emailNotifications: true, notifyEmail: 'careers@example.com', successMessage: 'Thank you for applying! Our hiring team will review your application and follow up within one week.', submitButtonText: 'Submit Application', requireAuth: false }
    },
    {
      name: 'product_review',
      display_name: 'Product Review',
      description: 'Leave a review for a product you purchased',
      category: 'feedback',
      formio_schema: {
        components: [
          { type: 'textfield', key: 'name', label: 'Your Name', validate: { required: true } },
          { type: 'email', key: 'email', label: 'Email', validate: { required: true } },
          { type: 'select', key: 'product', label: 'Product', data: { values: [
            { label: 'Premium Wireless Headphones', value: 'headphones' },
            { label: 'Smart Watch Pro', value: 'smartwatch' },
            { label: 'Mechanical Keyboard RGB', value: 'keyboard' },
            { label: 'HD Webcam 4K', value: 'webcam' },
            { label: 'Portable SSD 1TB', value: 'ssd' },
            { label: 'Monitor 27" 4K', value: 'monitor' }
          ] }, validate: { required: true } },
          { type: 'number', key: 'rating', label: 'Rating (1-5)', validate: { required: true, min: 1, max: 5 } },
          { type: 'textarea', key: 'review', label: 'Your Review', placeholder: 'Share your experience with this product...', validate: { required: true, maxLength: 2000 } },
          { type: 'checkbox', key: 'recommend', label: 'I would recommend this product to others' }
        ]
      },
      settings: { successMessage: 'Thank you for your review! It will appear on the product page after moderation.', submitButtonText: 'Submit Review', requireAuth: false }
    }
  ]

  // ============================================================================
  // Submission Data Pools
  // ============================================================================

  private messageTexts = [
    'I would like to learn more about your services and pricing options for our team.',
    'We are interested in scheduling a demo for our engineering department next week.',
    'Could you provide more details about the enterprise plan and SLA guarantees?',
    'I am having trouble integrating the API with our existing React application.',
    'Great product! Just wanted to say how much our team loves using it every day.',
    'Is there a way to export our data in CSV format from the admin dashboard?',
    'We are evaluating CMS platforms and would love to discuss a potential partnership.',
    'I noticed a minor issue with the search feature when using special characters.',
    'Can you help me set up custom webhooks for content change notifications?',
    'Our company is migrating from WordPress and would appreciate migration guidance.',
    'I am interested in contributing to the open-source project. Where can I start?',
    'The documentation is excellent but I could not find info about rate limiting.',
    'We need to set up SSO with our Azure AD tenant. Is this supported on the Pro plan?',
    'Just wanted to share some feedback — the new form builder is a huge improvement.',
    'Is it possible to schedule content publishing for a specific date and time?',
    'We are experiencing intermittent 502 errors on our production deployment.',
    'How does the AI search feature handle multi-language content?',
    'I would like to request a feature for bulk content import via CSV upload.'
  ]

  private feedbackComments = [
    'Great product overall. The interface is intuitive and the API is well-documented.',
    'Delivery was faster than expected. Very pleased with the build quality.',
    'Customer service was incredibly responsive. My issue was resolved in under an hour.',
    'The performance improvements in the latest release are very noticeable.',
    'I wish there were more customization options for the dashboard layout.',
    'Setup was straightforward — I had everything running in under 30 minutes.',
    'Good value for the price point. Comparable products cost significantly more.',
    'The mobile experience could use some polish but desktop is excellent.',
    'Documentation is comprehensive and the code examples are very helpful.',
    'We have been using this for 6 months and it has been rock solid in production.',
    'The search functionality works great, especially the full-text search mode.',
    'Would love to see more integrations with third-party services in future updates.',
    'Minor bugs occasionally but the team is quick to push fixes. Impressed.',
    'The form builder is powerful but has a small learning curve for complex forms.',
    'Best headless CMS we have tried. Migrating our entire content pipeline.'
  ]

  private coverLetterTexts = [
    'I am excited to apply for this position. With 5 years of experience in full-stack development and a passion for building performant web applications, I believe I would be a strong addition to your team. I have been following your open-source project for the past year and love the architecture decisions around edge computing.',
    'As a developer who has worked extensively with TypeScript, React, and cloud infrastructure, I am thrilled about this opportunity. In my current role, I lead a team of 4 engineers building real-time collaboration tools. I am particularly drawn to your company\'s focus on developer experience and open-source community.',
    'I am writing to express my interest in joining your engineering team. My background includes 3 years at a YC-backed startup where I built and scaled API services handling 10M+ requests daily. I am passionate about performance optimization and have contributed to several open-source projects in the Node.js ecosystem.',
    'This role aligns perfectly with my career goals and technical expertise. I have deep experience with Cloudflare Workers, D1, and edge computing patterns. I contributed to the Workers runtime documentation and have given talks at CloudflareConnect about serverless architectures. I would love to bring this expertise to your team.'
  ]

  private companyNames = [
    'Acme Corp', 'TechStart Inc', 'Global Systems LLC', 'Innovate Digital',
    'Summit Solutions', 'Nexus Technologies', 'Brightwave Media', 'Quantum Labs',
    'Evergreen Software', 'Pinnacle Consulting', 'Atlas Ventures', 'Horizon Health',
    'Velocity Partners', 'Sterling Analytics', 'Catalyst Group'
  ]

  private userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
  ]

  private referrers = [
    'https://www.google.com/', 'https://www.bing.com/', 'https://twitter.com/',
    'https://www.linkedin.com/', 'https://github.com/', 'https://news.ycombinator.com/',
    'https://www.reddit.com/', null
  ]

  private utmSources = ['google', 'twitter', 'linkedin', 'newsletter', 'facebook', 'github']
  private utmMediums = ['cpc', 'organic', 'email', 'social', 'referral']
  private utmCampaigns = ['spring-launch', 'developer-week', 'product-update', 'webinar-promo', 'year-end']

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }

  private generateSlug(title: string): string {
    return title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
  }

  private randomDate(): Date {
    const now = new Date()
    const yearAgo = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate())
    // Bias toward recent dates
    const t = Math.pow(Math.random(), 0.7)
    const randomTime = yearAgo.getTime() + t * (now.getTime() - yearAgo.getTime())
    return new Date(randomTime)
  }

  private pickRandom<T>(array: T[]): T {
    return array[Math.floor(Math.random() * array.length)]!
  }

  private generateTags(count?: number): string[] {
    const numTags = count || (Math.floor(Math.random() * 4) + 2) // 2-5 tags
    const shuffled = [...this.allTags].sort(() => 0.5 - Math.random())
    return shuffled.slice(0, numTags)
  }

  private generatePhoneNumber(): string {
    const area = Math.floor(Math.random() * 900) + 100
    const mid = Math.floor(Math.random() * 900) + 100
    const end = Math.floor(Math.random() * 9000) + 1000
    return `(${area}) ${mid}-${end}`
  }

  private generateEmail(index?: number): string {
    const first = this.pickRandom(this.firstNames).toLowerCase()
    const last = this.pickRandom(this.lastNames).toLowerCase()
    const n = index !== undefined ? index : Math.floor(Math.random() * 999)
    return `${first}.${last}${n}@example.com`
  }

  private generateIpAddress(): string {
    return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
  }

  private assembleMultiParagraphHtml(title: string, paragraphCount: number): string {
    const selected: string[] = []
    const shuffled = [...this.blogParagraphs].sort(() => 0.5 - Math.random())
    for (let i = 0; i < paragraphCount && i < shuffled.length; i++) {
      selected.push(shuffled[i]!)
    }

    let html = `<h1>${title}</h1>\n`
    const subheadings = ['Key Concepts', 'Practical Considerations', 'Best Practices', 'Looking Ahead', 'Implementation Details', 'Common Pitfalls']
    let subheadingIndex = 0

    for (let i = 0; i < selected.length; i++) {
      if (i > 0 && i % 2 === 0 && subheadingIndex < subheadings.length) {
        html += `<h2>${subheadings[subheadingIndex]}</h2>\n`
        subheadingIndex++
      }
      html += `<p>${selected[i]}</p>\n`
    }

    return html
  }

  // ============================================================================
  // Content Generation (Rich)
  // ============================================================================

  private generateRichBlogData(title: string, richness: 'minimal' | 'full'): any {
    if (richness === 'minimal') {
      return {
        body: this.pickRandom(this.blogParagraphs),
        excerpt: 'A brief introduction to this article that provides an overview of the main topics covered.',
        tags: this.generateTags(2),
        featured: Math.random() > 0.7
      }
    }

    const paragraphCount = Math.floor(Math.random() * 3) + 3 // 3-5 paragraphs
    return {
      body: this.assembleMultiParagraphHtml(title, paragraphCount),
      excerpt: this.pickRandom(this.blogExcerpts),
      tags: this.generateTags(),
      featured: Math.random() > 0.7,
      difficulty: this.pickRandom(['beginner', 'intermediate', 'advanced']),
      readingTime: `${Math.floor(Math.random() * 12) + 3} min read`,
      author: `${this.pickRandom(this.firstNames)} ${this.pickRandom(this.lastNames)}`
    }
  }

  private generateRichPageData(title: string, richness: 'minimal' | 'full'): any {
    if (richness === 'minimal') {
      return {
        body: 'This is a standard page with important information about our services and policies.',
        template: 'default',
        showInMenu: Math.random() > 0.5
      }
    }

    const templateContent = this.pageContentTemplates[title]
    const body = templateContent || this.assembleMultiParagraphHtml(title, 3)

    return {
      body,
      template: 'default',
      showInMenu: Math.random() > 0.3,
      metaDescription: `${title} — Learn more about our platform, services, and commitment to excellence.`,
      metaKeywords: this.generateTags(3)
    }
  }

  private generateRichProductData(title: string, richness: 'minimal' | 'full'): any {
    const price = (Math.random() * 500 + 10).toFixed(2)
    const sku = `SKU-${Math.random().toString(36).substr(2, 9).toUpperCase()}`
    const inStock = Math.random() > 0.2
    const rating = (Math.random() * 2 + 3).toFixed(1)

    if (richness === 'minimal') {
      return { description: 'High-quality product with excellent features and great value for money.', price, sku, inStock, rating }
    }

    const description = this.productDescriptions[title] || 'High-quality product with excellent features, premium materials, and outstanding value. Designed for professionals who demand the best from their tools.'

    return {
      description,
      price,
      sku,
      inStock,
      rating,
      reviewCount: Math.floor(Math.random() * 200) + 5,
      category: this.pickRandom(this.productCategories),
      brand: this.pickRandom(['TechPro', 'NovaTech', 'EliteGear', 'PrimeWare', 'Zenith']),
      featured: Math.random() > 0.7
    }
  }

  // ============================================================================
  // Submission Field Value Generation
  // ============================================================================

  private generateFieldValue(component: any, submissionIndex: number): any {
    const key = component.key || ''

    switch (component.type) {
      case 'textfield':
        if (key.includes('name') || key.includes('Name')) {
          if (key.includes('first') || key.includes('First')) return this.pickRandom(this.firstNames)
          if (key.includes('last') || key.includes('Last')) return this.pickRandom(this.lastNames)
          return `${this.pickRandom(this.firstNames)} ${this.pickRandom(this.lastNames)}`
        }
        if (key.includes('company') || key.includes('organization')) return this.pickRandom(this.companyNames)
        return `Sample text for ${key}`

      case 'email':
        return this.generateEmail(submissionIndex)

      case 'textarea':
        if (key.includes('cover') || key.includes('Cover')) return this.pickRandom(this.coverLetterTexts)
        if (key.includes('review') || key.includes('feedback') || key.includes('comment')) return this.pickRandom(this.feedbackComments)
        return this.pickRandom(this.messageTexts)

      case 'phoneNumber':
        return this.generatePhoneNumber()

      case 'number':
        const min = component.validate?.min ?? 1
        const max = component.validate?.max ?? 5
        return Math.floor(Math.random() * (max - min + 1)) + min

      case 'checkbox':
        return Math.random() > 0.3

      case 'radio': {
        const radioValues: any[] = component.values || []
        if (radioValues.length > 0) return this.pickRandom(radioValues).value
        return 'option1'
      }

      case 'select': {
        const selectValues: any[] = component.data?.values || component.values || []
        if (selectValues.length > 0) return this.pickRandom(selectValues).value
        return 'option1'
      }

      case 'selectboxes': {
        const boxes: Record<string, boolean> = {}
        const sbValues = component.values || []
        sbValues.forEach((v: any) => { boxes[v.value] = Math.random() > 0.5 })
        return boxes
      }

      case 'datetime':
        return this.randomDate().toISOString()

      case 'url':
        return this.pickRandom([
          'https://linkedin.com/in/johndoe',
          'https://github.com/developer',
          'https://portfolio.example.com',
          'https://example.com/page',
          'https://mysite.dev'
        ])

      default:
        return null
    }
  }

  // ============================================================================
  // Core Methods
  // ============================================================================

  async createUsers(userCount: number = 20): Promise<number> {
    const roles = ['admin', 'editor', 'author', 'viewer']
    const hashedPassword = 'password123' // TODO: Use actual bcrypt hash

    let count = 0
    for (let i = 0; i < userCount; i++) {
      const firstName = this.pickRandom(this.firstNames)
      const lastName = this.pickRandom(this.lastNames)
      const username = `${firstName.toLowerCase()}${lastName.toLowerCase()}${i}`
      const email = `${username}@example.com`
      const createdAt = this.randomDate()
      const createdAtTimestamp = Math.floor(createdAt.getTime() / 1000)

      await this.db.prepare(`
        INSERT INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, last_login_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        this.generateId(),
        email, username, firstName, lastName, hashedPassword,
        this.pickRandom(roles),
        Math.random() > 0.1 ? 1 : 0,
        Math.random() > 0.3 ? createdAtTimestamp : null,
        createdAtTimestamp, createdAtTimestamp
      ).run()

      count++
    }
    return count
  }

  async createContent(contentCount: number = 200, richness: 'minimal' | 'full' = 'full'): Promise<number> {
    const { results: allUsers } = await this.db.prepare('SELECT * FROM users').all()
    const { results: allCollections } = await this.db.prepare('SELECT * FROM collections').all()

    if (!allUsers || allUsers.length === 0) throw new Error('No users found. Please create users first.')
    if (!allCollections || allCollections.length === 0) throw new Error('No collections found. Please create collections first.')

    const statuses = ['draft', 'published', 'published', 'published', 'archived'] // weight toward published

    let count = 0
    for (let i = 0; i < contentCount; i++) {
      const collection: any = this.pickRandom(allCollections)
      const author: any = this.pickRandom(allUsers)
      const status = this.pickRandom(statuses)
      const name = (collection.name || '').toLowerCase()

      let title: string
      let contentData: any

      if (name === 'blog_posts' || name.includes('blog')) {
        title = this.pickRandom(this.blogTitles)
        contentData = this.generateRichBlogData(title, richness)
      } else if (name === 'pages' || name.includes('page')) {
        title = this.pickRandom(this.pageTitles)
        contentData = this.generateRichPageData(title, richness)
      } else if (name === 'products' || name.includes('product')) {
        title = this.pickRandom(this.productTitles)
        contentData = this.generateRichProductData(title, richness)
      } else {
        title = `${collection.display_name || collection.name} Item ${i + 1}`
        contentData = {
          description: richness === 'full'
            ? `This is a sample ${collection.display_name || collection.name} item with generated content for testing and development purposes.`
            : 'This is a sample content item with generic data.',
          value: Math.floor(Math.random() * 1000)
        }
      }

      const slug = `${this.generateSlug(title)}-${i}`
      const createdAt = this.randomDate()
      const createdAtTimestamp = Math.floor(createdAt.getTime() / 1000)
      const publishedAtTimestamp = status === 'published' ? createdAtTimestamp : null

      await this.db.prepare(`
        INSERT INTO content (id, collection_id, slug, title, data, status, published_at, author_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        this.generateId(), collection.id, slug, `${title} ${i}`,
        JSON.stringify(contentData), status, publishedAtTimestamp,
        author.id, createdAtTimestamp, createdAtTimestamp
      ).run()

      count++
    }
    return count
  }

  async createForms(formCount: number = 5, creatorUserId: string): Promise<{ forms: number; formIds: string[] }> {
    let count = 0
    const formIds: string[] = []

    for (let i = 0; i < formCount; i++) {
      const templateIndex = i % this.formTemplates.length
      const template = this.formTemplates[templateIndex]!
      const suffix = i >= this.formTemplates.length ? `_${Math.floor(i / this.formTemplates.length) + 1}` : ''
      const name = `${template.name}${suffix}`
      const displayName = suffix ? `${template.display_name} ${Math.floor(i / this.formTemplates.length) + 1}` : template.display_name

      const id = this.generateId()
      const now = Date.now()

      try {
        await this.db.prepare(`
          INSERT OR IGNORE INTO forms (
            id, name, display_name, description, category,
            formio_schema, settings, is_active, is_public,
            submission_count, created_by, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, 0, ?, ?, ?)
        `).bind(
          id, name, displayName, template.description, template.category,
          JSON.stringify(template.formio_schema),
          JSON.stringify(template.settings || {}),
          creatorUserId, now, now
        ).run()

        formIds.push(id)
        count++
      } catch (e) {
        // Skip duplicate names
        console.warn(`[Seed] Skipping form "${name}" — may already exist`)
      }
    }

    return { forms: count, formIds }
  }

  async createSubmissions(
    formId: string,
    formSchema: any,
    count: number,
    users: any[]
  ): Promise<number> {
    const components = formSchema?.components || []
    if (components.length === 0) return 0

    let created = 0
    for (let i = 0; i < count; i++) {
      const submissionData: Record<string, any> = {}

      for (const component of components) {
        if (component.key && component.type !== 'button') {
          submissionData[component.key] = this.generateFieldValue(component, i)
        }
      }

      const id = this.generateId()
      const submittedAt = Date.now() - Math.floor(Math.random() * 90 * 24 * 60 * 60 * 1000) // last 90 days
      const user = Math.random() > 0.5 && users.length > 0 ? this.pickRandom(users) : null
      const email = (submissionData.email as string) || this.generateEmail(i)
      const status = this.pickRandom(['pending', 'pending', 'pending', 'reviewed', 'approved'])

      await this.db.prepare(`
        INSERT INTO form_submissions (
          id, form_id, submission_data, status, user_id, user_email,
          ip_address, user_agent, referrer, utm_source, utm_medium, utm_campaign,
          submitted_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id, formId, JSON.stringify(submissionData), status,
        (user as any)?.id || null, email,
        this.generateIpAddress(),
        this.pickRandom(this.userAgents),
        this.pickRandom(this.referrers),
        Math.random() > 0.6 ? this.pickRandom(this.utmSources) : null,
        Math.random() > 0.6 ? this.pickRandom(this.utmMediums) : null,
        Math.random() > 0.7 ? this.pickRandom(this.utmCampaigns) : null,
        submittedAt, submittedAt
      ).run()

      created++
    }
    return created
  }

  async createAllFormsAndSubmissions(
    formCount: number = 5,
    submissionsPerForm: number = 15
  ): Promise<{ forms: number; submissions: number }> {
    // Get an admin user to be the form creator
    const { results: admins } = await this.db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").all()
    const creatorId = (admins?.[0] as any)?.id || 'system'

    // Get all users for submission assignment
    const { results: allUsers } = await this.db.prepare('SELECT id, email FROM users').all()

    // Create forms
    const { forms, formIds } = await this.createForms(formCount, creatorId)

    // Create submissions for each form
    let totalSubmissions = 0
    for (const formId of formIds) {
      // Get the form schema we just inserted
      const formRow = await this.db.prepare('SELECT formio_schema FROM forms WHERE id = ?').bind(formId).first<{ formio_schema: string }>()
      if (!formRow) continue

      const schema = JSON.parse(formRow.formio_schema)
      const created = await this.createSubmissions(formId, schema, submissionsPerForm, allUsers || [])
      totalSubmissions += created
    }

    return { forms, submissions: totalSubmissions }
  }

  async seedAll(options: SeedOptions): Promise<SeedResult> {
    const users = await this.createUsers(options.userCount)
    const content = await this.createContent(options.contentCount, options.richness)
    const { forms, submissions } = await this.createAllFormsAndSubmissions(
      options.formCount,
      options.submissionsPerForm
    )

    return { users, content, forms, submissions }
  }

  async clearSeedData(): Promise<void> {
    // Delete in FK-safe order
    await this.db.prepare('DELETE FROM form_submissions').run()
    await this.db.prepare('DELETE FROM forms').run()
    await this.db.prepare('DELETE FROM content').run()
    await this.db.prepare("DELETE FROM users WHERE role != 'admin'").run()
  }
}
