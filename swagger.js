const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Documentation',
      version: '1.0.0',
      description: 'API documentation for your Node.js application',
      contact: {
        name: 'API Support',
        email: 'support@example.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:5000',
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'integer', example: 1 },
            name: { type: 'string', example: 'John Doe' },
            email: { type: 'string', example: 'john@example.com' },
            address: { type: 'string', example: '123 Main St' },
            profile_pic: { type: 'string', example: 'profile.jpg' },
            phoneno: { type: 'string', example: '1234567890' },
            accountType: { type: 'string', example: 'personal' },
            created_at: { type: 'string', format: 'date-time' }
          }
        },
        LoginRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', example: 'user@example.com' },
            password: { type: 'string', example: 'yourpassword' }
          }
        },
        FollowAction: {
          type: 'object',
          required: ['userId', 'targetId', 'action'],
          properties: {
            userId: { type: 'integer', example: 1 },
            targetId: { type: 'integer', example: 2 },
            action: { type: 'string', enum: ['follow', 'unfollow'] },
            isRequest: { type: 'boolean', example: false }
          }
        }
      }
    }
  },
  apis: [
    './route/*.js',         
    './controllers/*.js'     
  ],
};

const specs = swaggerJsdoc(options);

module.exports = { specs, swaggerUi };