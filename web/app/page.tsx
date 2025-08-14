"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import {
  CheckCircle,
  Shield,
  Brain,
  Download,
  ExternalLink,
  AlertTriangle,
  Github,
  Terminal,
  Play,
  ArrowRight,
  ArrowLeft,
  Lock,
  Copy,
  Check,
} from "lucide-react"

interface FormData {
  repoUrl: string
  baseUrl: string
  authHeader: string
  unsafe: boolean
  ollamaModel: string
  concurrency: number
  delayMs: number
}

const steps = ["welcome", "prerequisites", "clone", "setup", "configure", "consent", "run", "results"] as const

type Step = (typeof steps)[number]

export default function AISecurityAgent() {
  const [currentStep, setCurrentStep] = useState<Step>("welcome")
  const [completedSteps, setCompletedSteps] = useState<Set<Step>>(new Set())
  const [copiedStates, setCopiedStates] = useState<Record<string, boolean>>({})
  const [formData, setFormData] = useState<FormData>({
    repoUrl: "",
    baseUrl: "",
    authHeader: "",
    unsafe: false,
    ollamaModel: "llama3.2:latest",
    concurrency: 3,
    delayMs: 200,
  })
  const [progress, setProgress] = useState(0)
  const [isRunning, setIsRunning] = useState(false)

  const completeStep = (step: Step) => {
    setCompletedSteps((prev) => new Set([...prev, step]))
  }

  const nextStep = () => {
    const currentIndex = steps.indexOf(currentStep)
    if (currentIndex < steps.length - 1) {
      completeStep(currentStep)
      setCurrentStep(steps[currentIndex + 1])
    }
  }

  const prevStep = () => {
    const currentIndex = steps.indexOf(currentStep)
    if (currentIndex > 0) {
      setCurrentStep(steps[currentIndex - 1])
    }
  }

  const generateCommand = () => {
    let cmd = `source .venv/bin/activate && python3 -m secagent.cli --repo "${formData.repoUrl}" --base-url "${formData.baseUrl}" --ollama-model "${formData.ollamaModel}" --concurrency ${formData.concurrency} --delay-ms ${formData.delayMs} --verbose`

    if (formData.authHeader) cmd += ` --auth-header "${formData.authHeader}"`
    if (formData.unsafe) cmd += ` --unsafe`

    return cmd
  }

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedStates((prev) => ({ ...prev, [id]: true }))
      setTimeout(() => {
        setCopiedStates((prev) => ({ ...prev, [id]: false }))
      }, 2000)
    } catch (err) {
      console.error("Failed to copy text: ", err)
    }
  }

  const simulateRun = () => {
    setIsRunning(true)
    setProgress(0)

    const phases = [
      { name: "Repository Ingestion", progress: 10 },
      { name: "Endpoint Discovery", progress: 30 },
      { name: "Normalization", progress: 50 },
      { name: "Test Planning", progress: 60 },
      { name: "Security Testing", progress: 80 },
      { name: "AI Report Generation", progress: 100 },
    ]

    let currentPhase = 0
    const interval = setInterval(() => {
      if (currentPhase < phases.length) {
        setProgress(phases[currentPhase].progress)
        currentPhase++
      } else {
        clearInterval(interval)
        setIsRunning(false)
        nextStep()
      }
    }, 2000)
  }

  const renderStep = () => {
    switch (currentStep) {
      case "welcome":
        return (
          <div className="min-h-screen flex items-center justify-center relative overflow-hidden">
            <div className="absolute inset-0 bg-black">
              <div className="absolute inset-0 bg-gradient-to-br from-green-500/5 via-transparent to-green-400/5"></div>

              {/* Geometric shapes inspired by Modal */}
              <div className="absolute top-1/4 right-1/4 w-64 h-32 bg-gradient-to-r from-green-400/20 to-green-500/10 transform rotate-12 rounded-lg blur-sm"></div>
              <div className="absolute bottom-1/3 right-1/3 w-48 h-24 bg-gradient-to-l from-green-300/15 to-green-600/5 transform -rotate-6 rounded-lg blur-sm"></div>
              <div className="absolute top-1/2 right-1/6 w-32 h-64 bg-gradient-to-b from-green-500/10 to-green-400/20 transform rotate-45 rounded-lg blur-sm"></div>
            </div>

            <div className="relative z-10 max-w-7xl mx-auto px-6">
              <div className="grid lg:grid-cols-2 gap-16 items-center">
                <div className="space-y-8">
                  <div className="space-y-6">
                    <h1 className="text-5xl lg:text-7xl font-bold text-white leading-tight">
                      <span className="text-green-400">AI security</span> that developers love
                    </h1>
                    <p className="text-xl text-gray-400 leading-relaxed max-w-lg">
                      Local AI-powered codebase analysis, comprehensive API testing, and intelligent vulnerability
                      detection.
                    </p>
                  </div>

                  <div className="flex gap-4">
                    <button
                      onClick={nextStep}
                      className="group relative px-8 py-4 bg-green-500 hover:bg-green-400 text-black font-medium rounded-lg transition-all duration-200 overflow-hidden flex-1 max-w-48"
                    >
                      <span className="relative z-10">Get Started</span>
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700 ease-in-out"></div>
                    </button>

                    <Button
                      variant="outline"
                      onClick={() => window.open("https://github.com/perlakay/rAPId", "_blank")}
                      className="px-8 py-4 border-gray-600 text-gray-300 hover:bg-gray-800 hover:border-gray-500 rounded-lg flex-1 max-w-48"
                    >
                      View on GitHub
                    </Button>
                  </div>

                  <div className="pt-8">
                    <div className="flex items-center gap-4 text-sm text-gray-500">
                      <div className="flex items-center gap-2">
                        <Lock className="h-4 w-4 text-green-400" />
                        <span>100% Local Processing</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Brain className="h-4 w-4 text-green-400" />
                        <span>AI-Powered Analysis</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="grid gap-4">
                    <div className="group p-6 bg-gray-900/50 border border-gray-800 rounded-xl hover:border-green-500/30 hover:bg-gray-900/70 transition-all duration-300">
                      <div className="flex items-start gap-4">
                        <div className="p-2 bg-green-500/10 rounded-lg">
                          <Shield className="h-6 w-6 text-green-400" />
                        </div>
                        <div>
                          <h3 className="text-lg font-medium text-white mb-2">Comprehensive Security Testing</h3>
                          <p className="text-gray-400 text-sm leading-relaxed">
                            Advanced pattern recognition with smart remediation suggestions for your codebase and APIs.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="group p-6 bg-gray-900/50 border border-gray-800 rounded-xl hover:border-green-500/30 hover:bg-gray-900/70 transition-all duration-300">
                      <div className="flex items-start gap-4">
                        <div className="p-2 bg-green-500/10 rounded-lg">
                          <Lock className="h-6 w-6 text-green-400" />
                        </div>
                        <div>
                          <h3 className="text-lg font-medium text-white mb-2">Privacy-First Architecture</h3>
                          <p className="text-gray-400 text-sm leading-relaxed">
                            Zero data transmission - everything stays on your machine with local Ollama processing.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="group p-6 bg-gray-900/50 border border-gray-800 rounded-xl hover:border-green-500/30 hover:bg-gray-900/70 transition-all duration-300">
                      <div className="flex items-start gap-4">
                        <div className="p-2 bg-green-500/10 rounded-lg">
                          <Brain className="h-6 w-6 text-green-400" />
                        </div>
                        <div>
                          <h3 className="text-lg font-medium text-white mb-2">Intelligent Analysis</h3>
                          <p className="text-gray-400 text-sm leading-relaxed">
                            Deep vulnerability detection with detailed reporting and actionable insights.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )

      case "prerequisites":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="flex items-center gap-3 text-green-400 text-xl">
                <CheckCircle className="h-6 w-6" />
                Prerequisites Check
              </CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Make sure you have these installed before proceeding
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <div className="space-y-4">
                <div className="flex items-center justify-between p-6 border border-green-500/10 rounded-xl bg-black/40 hover:border-green-500/30 hover:bg-black/60 transition-all duration-300">
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                    <span className="text-gray-300 text-lg">Python 3.11+</span>
                  </div>
                  <Badge variant="outline" className="border-green-500/40 text-green-400 bg-green-500/5">
                    Required
                  </Badge>
                </div>
                <div className="flex items-center justify-between p-6 border border-green-500/10 rounded-xl bg-black/40 hover:border-green-500/30 hover:bg-black/60 transition-all duration-300">
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                    <span className="text-gray-300 text-lg">Ollama (Local AI)</span>
                  </div>
                  <Badge variant="outline" className="border-green-500/40 text-green-400 bg-green-500/5">
                    Required
                  </Badge>
                </div>
                <div className="flex items-center justify-between p-6 border border-green-500/10 rounded-xl bg-black/40 hover:border-green-500/30 hover:bg-black/60 transition-all duration-300">
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                    <span className="text-gray-300 text-lg">Git</span>
                  </div>
                  <Badge variant="outline" className="border-green-500/40 text-green-400 bg-green-500/5">
                    Required
                  </Badge>
                </div>
              </div>

              <Alert className="border-green-500/20 bg-green-500/5 rounded-xl">
                <AlertTriangle className="h-5 w-5 text-green-400" />
                <AlertDescription className="text-gray-300 text-base">
                  Don't have Ollama?{" "}
                  <a
                    href="https://ollama.ai"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-green-400 hover:text-green-300 underline underline-offset-2"
                  >
                    Download it here
                  </a>{" "}
                  - it's free and runs AI models locally.
                </AlertDescription>
              </Alert>

              <div className="flex gap-4 pt-6">
                <Button
                  variant="outline"
                  onClick={prevStep}
                  className="border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <ArrowLeft className="mr-2 h-5 w-5" /> Back
                </Button>
                <Button
                  onClick={nextStep}
                  className="flex-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
                >
                  Continue <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )

      case "clone":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="flex items-center gap-3 text-green-400 text-xl">
                <Github className="h-6 w-6" />
                Clone Repository
              </CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Get the rAPId security agent on your machine
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <div className="relative p-6 bg-black/60 border border-green-500/10 rounded-xl">
                <code className="text-green-400 text-base pr-12">git clone https://github.com/perlakay/rAPId.git</code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copyToClipboard("git clone https://github.com/perlakay/rAPId.git", "git-clone")}
                  className="absolute top-4 right-4 h-8 w-8 p-0 text-gray-400 hover:text-green-400 hover:bg-green-500/10"
                >
                  {copiedStates["git-clone"] ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  onClick={() => window.open("https://github.com/perlakay/rAPId.git", "_blank")}
                  className="flex-1 border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <Github className="mr-2 h-5 w-5" />
                  Open GitHub Repo
                  <ExternalLink className="ml-2 h-5 w-5" />
                </Button>
              </div>

              <Alert className="border-green-500/20 bg-green-500/5 rounded-xl">
                <Terminal className="h-5 w-5 text-green-400" />
                <AlertDescription className="text-gray-300 text-base">
                  Run the git clone command in your terminal, then navigate to the rAPId directory with{" "}
                  <span className="inline-flex items-center gap-2">
                    <code className="bg-black/40 px-2 py-1 rounded text-green-400">cd rAPId</code>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard("cd rAPId", "cd-command")}
                      className="h-6 w-6 p-0 text-gray-400 hover:text-green-400"
                    >
                      {copiedStates["cd-command"] ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    </Button>
                  </span>
                </AlertDescription>
              </Alert>

              <div className="flex gap-4 pt-6">
                <Button
                  variant="outline"
                  onClick={prevStep}
                  className="border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <ArrowLeft className="mr-2 h-5 w-5" /> Back
                </Button>
                <Button
                  onClick={nextStep}
                  className="flex-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
                >
                  I've Cloned It <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )

      case "setup":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="flex items-center gap-3 text-green-400 text-xl">
                <Terminal className="h-6 w-6" />
                Setup Environment
              </CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Install dependencies and prepare the environment
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <div className="relative p-6 bg-black/60 border border-green-500/10 rounded-xl">
                <code className="text-green-400 text-base pr-12">./setup.sh</code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copyToClipboard("./setup.sh", "setup-command")}
                  className="absolute top-4 right-4 h-8 w-8 p-0 text-gray-400 hover:text-green-400 hover:bg-green-500/10"
                >
                  {copiedStates["setup-command"] ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>

              <Alert className="border-green-500/20 bg-green-500/5 rounded-xl">
                <Terminal className="h-5 w-5 text-green-400" />
                <AlertDescription className="text-gray-300 text-base">
                  This script will create a virtual environment and install all required Python packages. It may take a
                  few minutes.
                </AlertDescription>
              </Alert>

              <div className="space-y-4">
                <h4 className="font-semibold text-green-400 text-lg">What this does:</h4>
                <ul className="space-y-2 text-gray-300">
                  <li className="flex items-center gap-3">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Creates Python virtual environment
                  </li>
                  <li className="flex items-center gap-3">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Installs security analysis dependencies
                  </li>
                  <li className="flex items-center gap-3">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Sets up AI model integration
                  </li>
                  <li className="flex items-center gap-3">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Configures CLI tools
                  </li>
                </ul>
              </div>

              <div className="flex gap-4 pt-6">
                <Button
                  variant="outline"
                  onClick={prevStep}
                  className="border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <ArrowLeft className="mr-2 h-5 w-5" /> Back
                </Button>
                <Button
                  onClick={nextStep}
                  className="flex-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
                >
                  Setup Complete <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )

      case "configure":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="text-green-400 text-xl">Configure Analysis</CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Set up your repository and API details for security analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <div className="grid gap-6">
                <div className="space-y-3">
                  <Label htmlFor="repoUrl" className="text-green-400 text-base">
                    GitHub Repository URL *
                  </Label>
                  <Input
                    id="repoUrl"
                    placeholder="https://github.com/username/api-project"
                    value={formData.repoUrl}
                    onChange={(e) => setFormData((prev) => ({ ...prev, repoUrl: e.target.value }))}
                    className="bg-black/60 border-green-500/20 text-gray-300 placeholder:text-gray-500 focus:border-green-500/50 rounded-xl"
                  />
                </div>

                <div className="space-y-3">
                  <Label htmlFor="baseUrl" className="text-green-400 text-base">
                    API Base URL *
                  </Label>
                  <Input
                    id="baseUrl"
                    placeholder="https://api.example.com"
                    value={formData.baseUrl}
                    onChange={(e) => setFormData((prev) => ({ ...prev, baseUrl: e.target.value }))}
                    className="bg-black/60 border-green-500/20 text-gray-300 placeholder:text-gray-500 focus:border-green-500/50 rounded-xl"
                  />
                </div>

                <div className="space-y-3">
                  <Label htmlFor="authHeader" className="text-green-400 text-base">
                    Authentication Header (Optional)
                  </Label>
                  <Input
                    id="authHeader"
                    placeholder="Authorization: Bearer token123"
                    value={formData.authHeader}
                    onChange={(e) => setFormData((prev) => ({ ...prev, authHeader: e.target.value }))}
                    className="bg-black/60 border-green-500/20 text-gray-300 placeholder:text-gray-500 focus:border-green-500/50 rounded-xl"
                  />
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  <div className="space-y-3">
                    <Label htmlFor="ollamaModel" className="text-green-400 text-base">
                      AI Model
                    </Label>
                    <Select
                      value={formData.ollamaModel}
                      onValueChange={(value) => setFormData((prev) => ({ ...prev, ollamaModel: value }))}
                    >
                      <SelectTrigger className="bg-black/60 border-green-500/20 text-gray-300 focus:border-green-500/50 rounded-xl">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-black border-green-500/20">
                        <SelectItem value="llama3.2:latest">Llama 3.2 (Recommended)</SelectItem>
                        <SelectItem value="llama3.1:latest">Llama 3.1</SelectItem>
                        <SelectItem value="llama3:latest">Llama 3</SelectItem>
                        <SelectItem value="llama3:8b">Llama 3 8B</SelectItem>
                        <SelectItem value="llama3:70b">Llama 3 70B</SelectItem>
                        <SelectItem value="codellama:latest">CodeLlama</SelectItem>
                        <SelectItem value="codellama:7b">CodeLlama 7B</SelectItem>
                        <SelectItem value="codellama:13b">CodeLlama 13B</SelectItem>
                        <SelectItem value="mistral:latest">Mistral</SelectItem>
                        <SelectItem value="gemma:latest">Gemma</SelectItem>
                        <SelectItem value="phi3:latest">Phi-3</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-3">
                    <Label htmlFor="concurrency" className="text-green-400 text-base">
                      Concurrency
                    </Label>
                    <Input
                      id="concurrency"
                      type="number"
                      min="1"
                      max="10"
                      value={formData.concurrency}
                      onChange={(e) =>
                        setFormData((prev) => ({ ...prev, concurrency: Number.parseInt(e.target.value) || 3 }))
                      }
                      className="bg-black/60 border-green-500/20 text-gray-300 focus:border-green-500/50 rounded-xl"
                    />
                  </div>
                </div>

                <div className="flex items-center space-x-3 p-4 border border-green-500/10 rounded-xl bg-black/40">
                  <Checkbox
                    id="unsafe"
                    checked={formData.unsafe}
                    onCheckedChange={(checked) => setFormData((prev) => ({ ...prev, unsafe: !!checked }))}
                    className="border-green-500/40 data-[state=checked]:bg-green-500 data-[state=checked]:border-green-500"
                  />
                  <Label htmlFor="unsafe" className="text-gray-300">
                    Enable mutating requests (⚠️ Use with caution)
                  </Label>
                </div>
              </div>

              <div className="flex gap-4 pt-6">
                <Button
                  variant="outline"
                  onClick={prevStep}
                  className="border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <ArrowLeft className="mr-2 h-5 w-5" /> Back
                </Button>
                <Button
                  onClick={nextStep}
                  className="flex-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
                  disabled={!formData.repoUrl || !formData.baseUrl}
                >
                  Continue <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )

      case "consent":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="flex items-center gap-3 text-orange-400 text-xl">
                <AlertTriangle className="h-6 w-6" />
                Security Testing Consent
              </CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Important: Please read and confirm before proceeding
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <Alert className="border-orange-500/20 bg-orange-500/5 rounded-xl">
                <AlertTriangle className="h-5 w-5 text-orange-400" />
                <AlertDescription className="text-orange-300 text-base">
                  <strong>⚠️ SECURITY TESTING CONSENT ⚠️</strong>
                </AlertDescription>
              </Alert>

              <div className="space-y-4">
                <div className="flex items-start gap-3 p-4 border border-red-500/20 rounded-xl bg-red-500/5">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                  <span className="text-gray-300">Only test APIs you own or have explicit permission to test</span>
                </div>
                <div className="flex items-start gap-3 p-4 border border-red-500/20 rounded-xl bg-red-500/5">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                  <span className="text-gray-300">Testing may trigger security alerts in target systems</span>
                </div>
                <div className="flex items-start gap-3 p-4 border border-red-500/20 rounded-xl bg-red-500/5">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                  <span className="text-gray-300">Use --unsafe flag only when you understand the risks</span>
                </div>
                <div className="flex items-start gap-3 p-4 border border-red-500/20 rounded-xl bg-red-500/5">
                  <div className="w-2 h-2 bg-red-400 rounded-full mt-2"></div>
                  <span className="text-gray-300">Results may contain sensitive data - handle reports securely</span>
                </div>
                <div className="flex items-start gap-3 p-4 border border-green-500/20 rounded-xl bg-green-500/5">
                  <div className="w-2 h-2 bg-green-400 rounded-full mt-2"></div>
                  <span className="text-gray-300">All AI processing happens locally via Ollama</span>
                </div>
              </div>

              <Alert className="border-green-500/20 bg-green-500/5 rounded-xl">
                <Shield className="h-5 w-5 text-green-400" />
                <AlertDescription className="text-gray-300 text-base">
                  By proceeding, you confirm you have proper authorization to test the specified API endpoints.
                </AlertDescription>
              </Alert>

              <div className="flex gap-4 pt-6">
                <Button
                  variant="outline"
                  onClick={prevStep}
                  className="border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <ArrowLeft className="mr-2 h-5 w-5" /> Back
                </Button>
                <Button
                  onClick={nextStep}
                  className="flex-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
                >
                  I Understand & Consent <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </div>
            </CardContent>
          </Card>
        )

      case "run":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="flex items-center gap-3 text-green-400 text-xl">
                <Play className="h-6 w-6" />
                Run Security Analysis
              </CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Execute the AI-powered security scan
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <div className="relative p-6 bg-black/60 border border-green-500/10 rounded-xl">
                <div className="text-sm text-gray-400 mb-3">Generated Command:</div>
                <code className="text-green-400 text-sm break-all pr-12">{generateCommand()}</code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copyToClipboard(generateCommand(), "run-command")}
                  className="absolute top-4 right-4 h-8 w-8 p-0 text-gray-400 hover:text-green-400 hover:bg-green-500/10"
                >
                  {copiedStates["run-command"] ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>

              {isRunning && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-base font-medium text-green-400">Analysis Progress</span>
                    <span className="text-base text-gray-400">{progress}%</span>
                  </div>
                  <Progress value={progress} className="w-full h-3 bg-gray-800" />
                  <div className="text-base text-gray-300 p-4 bg-black/40 border border-green-500/10 rounded-xl">
                    {progress <= 10 && "📥 Repository Ingestion..."}
                    {progress > 10 && progress <= 30 && "🔍 Endpoint Discovery..."}
                    {progress > 30 && progress <= 50 && "📊 Normalization..."}
                    {progress > 50 && progress <= 60 && "📋 Test Planning..."}
                    {progress > 60 && progress <= 80 && "🧪 Security Testing..."}
                    {progress > 80 && "📄 AI Report Generation..."}
                  </div>
                </div>
              )}

              <div className="flex gap-4 pt-6">
                <Button
                  variant="outline"
                  onClick={prevStep}
                  disabled={isRunning}
                  className="border-green-500/20 text-green-400 hover:bg-green-500/10 bg-transparent hover:border-green-500/40 rounded-xl px-6 py-3"
                >
                  <ArrowLeft className="mr-2 h-5 w-5" /> Back
                </Button>
                <Button
                  onClick={simulateRun}
                  className="flex-1 bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
                  disabled={isRunning}
                >
                  {isRunning ? (
                    <>Running Analysis...</>
                  ) : (
                    <>
                      <Play className="mr-2 h-5 w-5" />
                      Start Analysis
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        )

      case "results":
        return (
          <Card className="max-w-2xl mx-auto bg-black/80 border-green-500/20 backdrop-blur-sm">
            <CardHeader className="border-b border-green-500/10">
              <CardTitle className="flex items-center gap-3 text-green-400 text-xl">
                <CheckCircle className="h-6 w-6" />
                Analysis Complete
              </CardTitle>
              <CardDescription className="text-gray-400 text-base">
                Your security analysis results are ready
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6 pt-8">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 border border-green-500/10 rounded-xl bg-black/40">
                  <div className="text-2xl font-bold text-blue-400">20</div>
                  <div className="text-sm text-gray-400">Endpoints</div>
                </div>
                <div className="text-center p-4 border border-green-500/10 rounded-xl bg-black/40">
                  <div className="text-2xl font-bold text-green-400">193</div>
                  <div className="text-sm text-gray-400">Tests</div>
                </div>
                <div className="text-center p-4 border border-green-500/10 rounded-xl bg-black/40">
                  <div className="text-2xl font-bold text-orange-400">3</div>
                  <div className="text-sm text-gray-400">Vulnerabilities</div>
                </div>
                <div className="text-center p-4 border border-green-500/10 rounded-xl bg-black/40">
                  <Badge variant="outline" className="border-orange-500/40 text-orange-400 bg-orange-500/5">
                    MEDIUM
                  </Badge>
                  <div className="text-sm text-gray-400 mt-2">Risk Level</div>
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="font-semibold text-green-400 text-lg">Download Reports</h4>
                <div className="grid gap-3">
                  <Button
                    variant="outline"
                    className="justify-start bg-black/40 border-green-500/20 text-green-400 hover:bg-green-500/10 hover:border-green-500/40 rounded-xl"
                  >
                    <Download className="mr-2 h-5 w-5" />
                    HTML Report (report.html)
                  </Button>
                  <Button
                    variant="outline"
                    className="justify-start bg-black/40 border-green-500/20 text-green-400 hover:bg-green-500/10 hover:border-green-500/40 rounded-xl"
                  >
                    <Download className="mr-2 h-5 w-5" />
                    Markdown Report (report.md)
                  </Button>
                  <Button
                    variant="outline"
                    className="justify-start bg-black/40 border-green-500/20 text-green-400 hover:bg-green-500/10 hover:border-green-500/40 rounded-xl"
                  >
                    <Download className="mr-2 h-5 w-5" />
                    Raw Data (security.db)
                  </Button>
                </div>
              </div>

              <Alert className="border-green-500/20 bg-green-500/5 rounded-xl">
                <Shield className="h-5 w-5 text-green-400" />
                <AlertDescription className="text-gray-300 text-base">
                  Reports contain detailed vulnerability analysis, remediation suggestions, and executive summaries.
                  Handle securely.
                </AlertDescription>
              </Alert>

              <Button
                onClick={() => {
                  setCurrentStep("welcome")
                  setCompletedSteps(new Set())
                  setFormData({
                    repoUrl: "",
                    baseUrl: "",
                    authHeader: "",
                    unsafe: false,
                    ollamaModel: "llama3.2:latest",
                    concurrency: 3,
                    delayMs: 200,
                  })
                }}
                className="w-full bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20 hover:border-green-500/50 rounded-xl px-6 py-3"
              >
                Run Another Analysis
              </Button>
            </CardContent>
          </Card>
        )

      default:
        return null
    }
  }

  return (
    <div className="min-h-screen bg-black text-gray-100">
      {currentStep !== "welcome" && (
        <div className="bg-black/90 border-b border-green-500/10 backdrop-blur-sm">
          <div className="container mx-auto py-6 px-4">
            <div className="max-w-2xl mx-auto">
              <div className="flex items-center justify-between text-sm text-gray-400 mb-4">
                <span>
                  Step {steps.indexOf(currentStep) + 1} of {steps.length}
                </span>
                <span>{Math.round(((steps.indexOf(currentStep) + 1) / steps.length) * 100)}% Complete</span>
              </div>
              <div className="w-full bg-gray-800/50 rounded-full h-3 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-green-500 to-green-400 transition-all duration-700 ease-out relative rounded-full"
                  style={{ width: `${((steps.indexOf(currentStep) + 1) / steps.length) * 100}%` }}
                >
                  <div className="absolute inset-0 bg-green-400/30 animate-pulse rounded-full"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="container mx-auto py-12 px-4">{renderStep()}</div>
    </div>
  )
}
