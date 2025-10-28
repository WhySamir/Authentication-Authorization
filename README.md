# Authentication-Authorization

Includes auth with jwt, bcrypt hashing, mongoose,nodemailer for otp in express

npm init -y

Installation:
`npm install express mongoose bcrypt cors jsonwebtoken nodemailer dotenv`

TS:

```npm install -D nodemon typescript ts-node @types/node @types/express @types/bcrypt @types/jsonwebtoken @types/cors @types/nodemailer

npx tsc --init
```

tsconfig.json

```
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "moduleResolution": "node",
    "rootDir": "./src",
    "outDir": "./dist",
    "baseUrl": "./src",
    "paths": {
      "*": ["*"]
    },
    "types": ["node"],
    "esModuleInterop": true,
    "strict": true,
    "sourceMap": true,
    "declaration": true,
    "declarationMap": true,
    "resolveJsonModule": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "src/tests/**/*"]
}
```
