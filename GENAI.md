# GEN_AI Project Documentation

## Project Overview
This is a comprehensive AI-powered application that provides document upload, processing, training, and chat functionality using modern microservices architecture.

## 🏗️ Architecture

### Microservices Architecture
- **Gateway Service** (Go) - API Gateway and authentication
- **Chat Service** (Python/FastAPI) - RAG-based chat functionality
- **Model Server** (Python/FastAPI) - AI model inference
- **Ingestion Worker** (Python/FastAPI) - Document processing and embedding
- **Frontend** (React/TypeScript) - User interface
- **Redis** - Caching and job queue
- **ChromaDB** - Vector database for embeddings

## 🛠️ Technologies & Tools Used

### Backend Technologies

#### Go (Golang)
- **Framework**: Gin Web Framework
- **Authentication**: JWT (JSON Web Tokens)
- **Database**: Redis client
- **HTTP Client**: Built-in net/http
- **Logging**: Zap logger
- **Configuration**: YAML-based config

#### Python
- **Framework**: FastAPI
- **ASGI Server**: Uvicorn
- **Data Validation**: Pydantic v1.10.13
- **HTTP Client**: httpx
- **Async Support**: asyncio
- **Environment**: python-dotenv

### AI/ML Technologies

#### Model Server
- **Base Model**: microsoft/DialoGPT-medium
- **Framework**: Hugging Face Transformers 4.30.2
- **PyTorch**: 2.0.1 (CPU-compatible)
- **Inference Engine**: Transformers pipeline
- **Tokenization**: AutoTokenizer
- **Model Loading**: AutoModelForCausalLM

#### Vector Database & Embeddings
- **Vector Database**: ChromaDB 0.4.24
- **Embedding Model**: Sentence Transformers 2.2.2
- **Similarity Search**: HNSW-based indexing
- **Document Chunking**: Custom chunking with overlap

#### RAG (Retrieval-Augmented Generation)
- **Implementation**: Custom RAG service
- **Context Building**: Dynamic prompt construction
- **Source Extraction**: Document relevance scoring
- **Caching**: Redis-based response caching

### Frontend Technologies

#### React Ecosystem
- **Framework**: React 18
- **Language**: TypeScript
- **UI Library**: Material-UI (MUI) v5
- **HTTP Client**: Axios
- **File Upload**: react-dropzone
- **State Management**: React Context API
- **Routing**: React Router

#### UI Components
- **Layout**: Responsive design with MUI Grid/Box
- **Forms**: MUI FormControl, TextField, Select
- **Data Display**: Tables, Cards, Lists
- **Feedback**: Alerts, Progress indicators, Chips
- **Navigation**: AppBar, Drawer, Tabs

### Infrastructure & DevOps

#### Containerization
- **Container Platform**: Docker
- **Orchestration**: Docker Compose
- **Multi-stage Builds**: Optimized Dockerfiles
- **Base Images**: 
  - Go: golang:1.21-alpine
  - Python: python:3.11-slim
  - Frontend: nginx:alpine

#### Database & Caching
- **Redis**: 7-alpine (Caching, job queues, session storage)
- **ChromaDB**: 0.4.24 (Vector storage and retrieval)

#### Networking
- **Service Discovery**: Docker internal networking
- **Load Balancing**: Nginx reverse proxy
- **CORS**: Cross-origin resource sharing
- **Authentication**: JWT-based stateless auth

## 🤖 AI Models Used

### Primary Model
- **Name**: microsoft/DialoGPT-medium
- **Type**: Conversational AI model
- **Size**: Medium (345M parameters)
- **Use Case**: Chat responses and text generation
- **Inference**: CPU-based (no GPU required)

### Embedding Model
- **Framework**: Sentence Transformers
- **Model**: Default embedding model from sentence-transformers
- **Use Case**: Document vectorization and similarity search
- **Output**: 768-dimensional vectors

### Model Configuration
- **Max Tokens**: 1024
- **Temperature**: 0.7
- **Top-P**: 0.9
- **Device**: CPU (optimized for compatibility)

## 📁 Project Structure

```
GEN_AI/
├── gateway/                 # Go API Gateway
│   ├── cmd/gateway/        # Main application
│   ├── internal/           # Internal packages
│   │   ├── handlers/       # HTTP handlers
│   │   ├── middleware/     # Auth, CORS, logging
│   │   ├── models/         # Data structures
│   │   └── config/         # Configuration
│   └── Dockerfile
├── services/
│   ├── chat_service/       # Python FastAPI chat service
│   │   ├── app/
│   │   │   ├── api/routes/ # API endpoints
│   │   │   ├── services/   # Business logic
│   │   │   ├── models/    # Pydantic models
│   │   │   └── core/      # Configuration
│   │   └── requirements.txt
│   └── ingestion_worker/   # Document processing service
├── model_server/           # AI model inference service
│   ├── scripts/           # Model loading scripts
│   └── Dockerfile
├── frontend/              # React frontend
│   ├── src/
│   │   ├── components/   # Reusable components
│   │   ├── pages/        # Page components
│   │   ├── contexts/     # React contexts
│   │   └── utils/        # Utility functions
│   └── package.json
└── infra/
    └── docker-compose.yml # Service orchestration
```

## 🔧 Key Features Implemented

### 1. Document Upload & Processing
- **File Upload**: Drag-and-drop interface
- **Processing**: Asynchronous document processing
- **Chunking**: Configurable chunk size and overlap
- **Embedding**: Automatic vector generation
- **Storage**: ChromaDB vector storage

### 2. Training System
- **Dataset Selection**: Multiple dataset support
- **Training Jobs**: Asynchronous training execution
- **Progress Tracking**: Real-time status updates
- **LoRA Configuration**: Low-rank adaptation settings
- **Model Management**: Adapter storage and retrieval

### 3. Chat Functionality
- **RAG Integration**: Retrieval-augmented generation
- **Context Awareness**: Document-based responses
- **Caching**: Response caching for performance
- **Streaming**: Real-time response streaming
- **Source Attribution**: Document source tracking

### 4. Admin Dashboard
- **System Monitoring**: Service health checks
- **Upload Management**: Upload job tracking
- **Training Overview**: Training job monitoring
- **Statistics**: System usage metrics

## 🚀 Deployment & Operations

### Docker Services
- **Gateway**: Port 8080
- **Chat Service**: Port 8001
- **Model Server**: Port 8003
- **Ingestion Worker**: Port 8002
- **Frontend**: Port 3000
- **Redis**: Port 6379
- **ChromaDB**: Port 8000

### Environment Configuration
- **Development**: Local Docker Compose
- **Production Ready**: Scalable microservices
- **Health Checks**: Built-in health monitoring
- **Logging**: Structured logging across services

## 🔐 Security Features

### Authentication & Authorization
- **JWT Tokens**: Stateless authentication
- **Role-based Access**: Admin and user roles
- **Rate Limiting**: Request rate limiting
- **CORS Protection**: Cross-origin security

### Data Security
- **Input Validation**: Pydantic model validation
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Input sanitization
- **Secure Headers**: Security headers implementation

## 📊 Performance Optimizations

### Caching Strategy
- **Redis Caching**: Response and session caching
- **Vector Caching**: Embedding result caching
- **CDN Ready**: Static asset optimization

### Scalability Features
- **Horizontal Scaling**: Stateless services
- **Load Balancing**: Nginx reverse proxy
- **Database Optimization**: Indexed vector search
- **Async Processing**: Non-blocking operations

## 🧪 Testing & Quality

### Code Quality
- **Type Safety**: TypeScript and Go type checking
- **Linting**: ESLint and Go vet
- **Formatting**: Prettier and gofmt
- **Error Handling**: Comprehensive error management

### Monitoring
- **Health Checks**: Service health monitoring
- **Logging**: Structured logging with Zap
- **Metrics**: Performance metrics collection
- **Debugging**: Comprehensive debug information

## 📈 Future Enhancements

### Planned Features
- **GPU Support**: CUDA-enabled model server
- **Advanced Models**: Support for larger language models
- **Fine-tuning**: Custom model training capabilities
- **Multi-tenancy**: Multi-user support
- **API Versioning**: Backward compatibility

### Scalability Improvements
- **Kubernetes**: Container orchestration
- **Service Mesh**: Istio integration
- **Database Sharding**: Horizontal database scaling
- **CDN Integration**: Global content delivery

## 🎯 Skills Demonstrated

### Backend Development
- **Go Programming**: Microservices, HTTP servers, middleware
- **Python Development**: FastAPI, async programming, data processing
- **API Design**: RESTful APIs, OpenAPI documentation
- **Database Design**: Vector databases, caching strategies

### Frontend Development
- **React Development**: Component architecture, state management
- **TypeScript**: Type-safe frontend development
- **Material-UI**: Modern UI component library
- **Responsive Design**: Mobile-first approach

### AI/ML Engineering
- **Model Integration**: Hugging Face transformers
- **RAG Implementation**: Retrieval-augmented generation
- **Vector Databases**: ChromaDB integration
- **Embedding Models**: Sentence transformers

### DevOps & Infrastructure
- **Docker**: Containerization and orchestration
- **Docker Compose**: Multi-service deployment
- **Microservices**: Service-oriented architecture
- **Monitoring**: Health checks and logging

### System Architecture
- **API Gateway**: Request routing and authentication
- **Event-driven Architecture**: Asynchronous processing
- **Caching Strategies**: Redis-based caching
- **Security**: JWT authentication, CORS, rate limiting

---

## 📝 Summary

This project demonstrates a full-stack AI application with modern microservices architecture, featuring:

- **7 different services** working together seamlessly
- **3 programming languages** (Go, Python, TypeScript)
- **AI model integration** with Hugging Face transformers
- **Vector database** for semantic search
- **RAG implementation** for intelligent responses
- **Docker containerization** for easy deployment
- **Modern frontend** with React and Material-UI
- **Comprehensive authentication** and security
- **Real-time features** with WebSocket support
- **Production-ready** monitoring and logging

The application successfully handles document processing, AI model training, and intelligent chat functionality while maintaining high performance and scalability.
