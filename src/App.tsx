import React, { useState, useEffect } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Button } from './components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, SelectGroup, SelectLabel } from './components/ui/select';
import { Slider } from './components/ui/slider';
import { Switch } from './components/ui/switch';
import { Textarea } from './components/ui/textarea';
import { ScrollArea } from './components/ui/scroll-area';
import { Separator } from './components/ui/separator';
import { Badge } from './components/ui/badge';
import { 
  AlertCircle, Lock, Unlock, Copy, Check, RefreshCw, Key, FileText, 
  Info, Wand2, Github, Sparkles, BookOpen, Shield, Brain, 
  KeyRound, Fingerprint, Shuffle, Grid, Rows, LayoutGrid, 
  Combine, SplitSquareHorizontal, Boxes, Layers
} from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from './components/ui/alert';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './components/ui/tooltip';
import { 
  atbashCipher, caesarCipher, affineCipher, vigenereCipher,
  gronsfeldCipher, beaufortCipher, autoKeyCipher, runningKeyCipher,
  hillCipher, railFenceCipher, routeCipher, columnarCipher,
  doubleTranspositionCipher, myszkowskiCipher, grillesCipher
} from './lib/ciphers';

type AlgorithmConfig = {
  name: string;
  description: string;
  icon: React.ReactNode;
  category: 'substitution' | 'polyalphabetic' | 'polygraphic' | 'transposition';
  subcategory: 'monoalphabetic' | 'multiple' | 'none';
};

const algorithms: Record<string, AlgorithmConfig> = {
  // Single Substitution - Monoalphabetic
  atbash: {
    name: 'Atbash Cipher',
    description: 'A simple substitution cipher that reverses the alphabet',
    icon: <Shuffle className="h-5 w-5" />,
    category: 'substitution',
    subcategory: 'monoalphabetic'
  },
  caesar: {
    name: 'Caesar Cipher',
    description: 'Shifts each letter by a fixed number of positions',
    icon: <KeyRound className="h-5 w-5" />,
    category: 'substitution',
    subcategory: 'monoalphabetic'
  },
  affine: {
    name: 'Affine Cipher',
    description: 'Uses a mathematical function to substitute letters',
    icon: <Brain className="h-5 w-5" />,
    category: 'substitution',
    subcategory: 'monoalphabetic'
  },
  
  // Multiple Substitution - Polyalphabetic
  vigenere: {
    name: 'Vigenère Cipher',
    description: 'A polyalphabetic substitution cipher using a keyword',
    icon: <Key className="h-5 w-5" />,
    category: 'polyalphabetic',
    subcategory: 'none'
  },
  gronsfeld: {
    name: 'Gronsfeld Cipher',
    description: 'Similar to Vigenère but uses numbers as the key',
    icon: <Fingerprint className="h-5 w-5" />,
    category: 'polyalphabetic',
    subcategory: 'none'
  },
  beaufort: {
    name: 'Beaufort Cipher',
    description: 'A reciprocal cipher related to the Vigenère cipher',
    icon: <Shield className="h-5 w-5" />,
    category: 'polyalphabetic',
    subcategory: 'none'
  },
  autokey: {
    name: 'Auto Key Cipher',
    description: 'Uses the plaintext itself as part of the key',
    icon: <Combine className="h-5 w-5" />,
    category: 'polyalphabetic',
    subcategory: 'none'
  },
  running: {
    name: 'Running Key Cipher',
    description: 'Uses a long text as the key',
    icon: <BookOpen className="h-5 w-5" />,
    category: 'polyalphabetic',
    subcategory: 'none'
  },
  
  // Multiple Substitution - Polygraphic
  hill: {
    name: 'Hill Cipher',
    description: 'Uses matrix multiplication for encryption',
    icon: <Grid className="h-5 w-5" />,
    category: 'polygraphic',
    subcategory: 'none'
  },
  
  // Transposition Ciphers
  railfence: {
    name: 'Rail Fence Cipher',
    description: 'Writes text in a zigzag pattern',
    icon: <Rows className="h-5 w-5" />,
    category: 'transposition',
    subcategory: 'none'
  },
  route: {
    name: 'Route Cipher',
    description: 'Writes text in a grid and reads it in a specific pattern',
    icon: <LayoutGrid className="h-5 w-5" />,
    category: 'transposition',
    subcategory: 'none'
  },
  columnar: {
    name: 'Columnar Cipher',
    description: 'Arranges text in columns and reads by column order',
    icon: <SplitSquareHorizontal className="h-5 w-5" />,
    category: 'transposition',
    subcategory: 'none'
  },
  double: {
    name: 'Double Transposition',
    description: 'Applies columnar transposition twice',
    icon: <Boxes className="h-5 w-5" />,
    category: 'transposition',
    subcategory: 'none'
  },
  myszkowski: {
    name: 'Myszkowski Cipher',
    description: 'A variation of the columnar transposition cipher',
    icon: <Layers className="h-5 w-5" />,
    category: 'transposition',
    subcategory: 'none'
  },
  grilles: {
    name: 'Grilles Cipher',
    description: 'Uses a perforated card for transposition',
    icon: <Grid className="h-5 w-5" />,
    category: 'transposition',
    subcategory: 'none'
  }
};

function App() {
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(true);
  const [showSteps, setShowSteps] = useState(false);
  const [steps, setSteps] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('caesar');
  const [caesarKey, setCaesarKey] = useState(3);
  const [affineKeyA, setAffineKeyA] = useState(5);
  const [affineKeyB, setAffineKeyB] = useState(8);
  const [vigenereKey, setVigenereKey] = useState('SECRET');
  const [railsCount, setRailsCount] = useState(3);
  const [routeRows, setRouteRows] = useState(3);
  const [routeCols, setRouteCols] = useState(4);
  const [hillMatrix, setHillMatrix] = useState([[5, 8], [3, 7]]); // For Hill cipher
  const [doubleTranspositionKey1, setDoubleTranspositionKey1] = useState('3124'); // For double transposition
  const [doubleTranspositionKey2, setDoubleTranspositionKey2] = useState('2413'); // For double transposition
  const [grillePattern, setGrillePattern] = useState('1000\n0001\n0010\n0100'); // For grilles cipher

  // const processText = () => {
  //   setError(null);
  //   setSteps([]);
  //   const newSteps: string[] = [];

  //   try {
  //     let result = '';
  //     switch (selectedAlgorithm) {
  //       case 'atbash':
  //         result = atbashCipher(inputText, newSteps);
  //         break;
  //       case 'caesar':
  //         result = caesarCipher(inputText, caesarKey, isEncrypting, newSteps);
  //         break;
  //       case 'affine':
  //         result = affineCipher(inputText, affineKeyA, affineKeyB, isEncrypting, newSteps);
  //         break;
  //       case 'vigenere':
  //         result = vigenereCipher(inputText, vigenereKey, isEncrypting, newSteps);
  //         break;
  //       case 'railfence':
  //         result = railFenceCipher(inputText, railsCount, isEncrypting, newSteps);
  //         break;
  //       case 'route':
  //         result = routeCipher(inputText, routeRows, routeCols, isEncrypting, newSteps);
  //         break;
  //       default:
  //         throw new Error('Algorithm not implemented');
  //     }
  //     setOutputText(result);
  //     setSteps(newSteps);
  //   } catch (err) {
  //     setError(err instanceof Error ? err.message : 'An error occurred');
  //     setOutputText('');
  //   }
  // };

  const processText = () => {
    setError(null);
    setSteps([]);
    const newSteps: string[] = [];
  
    try {
      let result = '';
      switch (selectedAlgorithm) {
        case 'atbash':
          result = atbashCipher(inputText, newSteps);
          break;
        case 'caesar':
          result = caesarCipher(inputText, caesarKey, isEncrypting, newSteps);
          break;
        case 'affine':
          result = affineCipher(inputText, affineKeyA, affineKeyB, isEncrypting, newSteps);
          break;
        case 'vigenere':
          result = vigenereCipher(inputText, vigenereKey, isEncrypting, newSteps);
          break;
        case 'gronsfeld':
          result = gronsfeldCipher(inputText, vigenereKey, isEncrypting, newSteps);
          break;
        case 'beaufort':
          result = beaufortCipher(inputText, vigenereKey, newSteps);
          break;
        case 'autokey':
          result = autoKeyCipher(inputText, vigenereKey, isEncrypting, newSteps);
          break;
        case 'running':
          result = runningKeyCipher(inputText, vigenereKey, isEncrypting, newSteps);
          break;
        case 'hill':
          // Using a simple 2x2 matrix for Hill cipher
          const hillMatrix = [[5, 8], [3, 7]]; // Example matrix with determinant coprime to 26
          result = hillCipher(inputText, hillMatrix, isEncrypting, newSteps);
          break;
        case 'railfence':
          result = railFenceCipher(inputText, railsCount, isEncrypting, newSteps);
          break;
        case 'route':
          result = routeCipher(inputText, routeRows, routeCols, isEncrypting, newSteps);
          break;
        case 'columnar':
          result = columnarCipher(inputText, vigenereKey, isEncrypting, newSteps);
          break;
        case 'double':
          // Using simple keys for double transposition
          result = doubleTranspositionCipher(inputText, '3124', '2413', isEncrypting, newSteps);
          break;
        case 'myszkowski':
          result = myszkowskiCipher(inputText, vigenereKey, isEncrypting, newSteps);
          break;
        case 'grilles':
          // Using a simple 4x4 grille pattern
          const grillePattern = '1000\n0001\n0010\n0100';
          result = grillesCipher(inputText, grillePattern, isEncrypting, newSteps);
          break;
        default:
          throw new Error('Algorithm not implemented');
      }
      setOutputText(result);
      setSteps(newSteps);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setOutputText('');
    }
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(outputText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const swapTexts = () => {
    setInputText(outputText);
    setOutputText('');
    setSteps([]);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      <div className="hero-gradient">
        <div className="container mx-auto py-12 px-4">
          <header className="text-center mb-12 animate-float">
            <div className="inline-flex items-center gap-3 mb-4">
              <div className="p-3 rounded-xl bg-blue-500/10 animate-pulse-slow">
                <Sparkles className="h-8 w-8 text-blue-600" />
              </div>
              <h1 className="text-4xl font-bold text-gradient animate-gradient">
                Cryptography Toolkit
              </h1>
            </div>
            <p className="text-gray-600 text-lg max-w-2xl mx-auto">
              Explore the fascinating world of classical cryptography with 15 different algorithms
            </p>
          </header>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <Card className="col-span-1 card-gradient card-hover backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-gray-800">
                  <FileText className="h-5 w-5 text-blue-600" />
                  Input
                </CardTitle>
                <CardDescription>Enter the text to process</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <Textarea 
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                    placeholder="Enter text to encrypt or decrypt..."
                    className="min-h-[200px] input-ring"
                  />
                  <div className="flex items-center space-x-2">
                    <Switch 
                      id="encryption-mode"
                      checked={isEncrypting}
                      onCheckedChange={setIsEncrypting}
                      className="data-[state=checked]:bg-green-500 data-[state=unchecked]:bg-amber-500"
                    />
                    <Label htmlFor="encryption-mode" className="cursor-pointer">
                      {isEncrypting ? (
                        <span className="flex items-center gap-1 text-green-600">
                          <Lock className="h-4 w-4" /> Encrypting
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-amber-600">
                          <Unlock className="h-4 w-4" /> Decrypting
                        </span>
                      )}
                    </Label>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="col-span-1 lg:col-span-2 card-gradient card-hover backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-gray-800">
                  <Key className="h-5 w-5 text-blue-600" />
                  Algorithm & Settings
                </CardTitle>
                <CardDescription>Select algorithm and configure parameters</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Algorithm</Label>
                    <Select 
                      value={selectedAlgorithm} 
                      onValueChange={setSelectedAlgorithm}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select algorithm" />
                      </SelectTrigger>
                      <SelectContent>
                        <ScrollArea className="h-[300px]">
                          {/* Single Substitution - Monoalphabetic */}
                          <SelectGroup>
                            <SelectLabel className="font-bold text-blue-600">Single Substitution - Monoalphabetic</SelectLabel>
                            {Object.entries(algorithms)
                              .filter(([_, config]) => config.category === 'substitution' && config.subcategory === 'monoalphabetic')
                              .map(([key, config]) => (
                                <SelectItem key={key} value={key}>
                                  <div className="flex items-center gap-2">
                                    <div className="text-blue-600">{config.icon}</div>
                                    <div>
                                      <div className="font-medium">{config.name}</div>
                                      <div className="text-xs text-gray-500">{config.description}</div>
                                    </div>
                                  </div>
                                </SelectItem>
                              ))}
                          </SelectGroup>

                          <Separator className="my-2" />

                          {/* Multiple Substitution - Polyalphabetic */}
                          <SelectGroup>
                            <SelectLabel className="font-bold text-blue-600">Multiple Substitution - Polyalphabetic</SelectLabel>
                            {Object.entries(algorithms)
                              .filter(([_, config]) => config.category === 'polyalphabetic')
                              .map(([key, config]) => (
                                <SelectItem key={key} value={key}>
                                  <div className="flex items-center gap-2">
                                    <div className="text-blue-600">{config.icon}</div>
                                    <div>
                                      <div className="font-medium">{config.name}</div>
                                      <div className="text-xs text-gray-500">{config.description}</div>
                                    </div>
                                  </div>
                                </SelectItem>
                              ))}
                          </SelectGroup>

                          <Separator className="my-2" />

                          {/* Multiple Substitution - Polygraphic */}
                          <SelectGroup>
                            <SelectLabel className="font-bold text-blue-600">Multiple Substitution - Polygraphic</SelectLabel>
                            {Object.entries(algorithms)
                              .filter(([_, config]) => config.category === 'polygraphic')
                              .map(([key, config]) => (
                                <SelectItem key={key} value={key}>
                                  <div className="flex items-center gap-2">
                                    <div className="text-blue-600">{config.icon}</div>
                                    <div>
                                      <div className="font-medium">{config.name}</div>
                                      <div className="text-xs text-gray-500">{config.description}</div>
                                    </div>
                                  </div>
                                </SelectItem>
                              ))}
                          </SelectGroup>

                          <Separator className="my-2" />

                          {/* Transposition Ciphers */}
                          <SelectGroup>
                            <SelectLabel className="font-bold text-blue-600">Transposition Ciphers</SelectLabel>
                            {Object.entries(algorithms)
                              .filter(([_, config]) => config.category === 'transposition')
                              .map(([key, config]) => (
                                <SelectItem key={key} value={key}>
                                  <div className="flex items-center gap-2">
                                    <div className="text-blue-600">{config.icon}</div>
                                    <div>
                                      <div className="font-medium">{config.name}</div>
                                      <div className="text-xs text-gray-500">{config.description}</div>
                                    </div>
                                  </div>
                                </SelectItem>
                              ))}
                          </SelectGroup>
                        </ScrollArea>
                      </SelectContent>
                    </Select>
                  </div>

                  {selectedAlgorithm === 'caesar' && (
                    <div className="space-y-2">
                      <Label>Shift Key (1-25)</Label>
                      <Slider
                        value={[caesarKey]}
                        onValueChange={([value]) => setCaesarKey(value)}
                        max={25}
                        min={1}
                        step={1}
                      />
                      <div className="text-sm text-gray-500">Current shift: {caesarKey}</div>
                    </div>
                  )}

                  {selectedAlgorithm === 'affine' && (
                    <>
                      <div className="space-y-2">
                        <Label>Key A (must be coprime with 26)</Label>
                        <Input
                          type="number"
                          value={affineKeyA}
                          onChange={(e) => setAffineKeyA(parseInt(e.target.value))}
                          min={1}
                          className="input-ring"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Key B (0-25)</Label>
                        <Input
                          type="number"
                          value={affineKeyB}
                          onChange={(e) => setAffineKeyB(parseInt(e.target.value))}
                          min={0}
                          max={25}
                          className="input-ring"
                        />
                      </div>
                    </>
                  )}

                  {selectedAlgorithm === 'vigenere' && (
                    <div className="space-y-2">
                      <Label>Key (text)</Label>
                      <Input
                        value={vigenereKey}
                        onChange={(e) => setVigenereKey(e.target.value)}
                        placeholder="Enter key..."
                        className="input-ring"
                      />
                    </div>
                  )}

                  {selectedAlgorithm === 'railfence' && (
                    <div className="space-y-2">
                      <Label>Number of Rails (2-10)</Label>
                      <Slider
                        value={[railsCount]}
                        onValueChange={([value]) => setRailsCount(value)}
                        max={10}
                        min={2}
                        step={1}
                      />
                      <div className="text-sm text-gray-500">Current rails: {railsCount}</div>
                    </div>
                  )}

                  {selectedAlgorithm === 'route' && (
                    <>
                      <div className="space-y-2">
                        <Label>Rows (2-10)</Label>
                        <Slider
                          value={[routeRows]}
                          onValueChange={([value]) => setRouteRows(value)}
                          max={10}
                          min={2}
                          step={1}
                        />
                        <div className="text-sm text-gray-500">Current rows: {routeRows}</div>
                      </div>
                      <div className="space-y-2">
                        <Label>Columns (2-10)</Label>
                        <Slider
                          value={[routeCols]}
                          onValueChange={([value]) => setRouteCols(value)}
                          max={10}
                          min={2}
                          step={1}
                        />
                        <div className="text-sm text-gray-500">Current columns: {routeCols}</div>
                      </div>
                    </>
                  )}

{selectedAlgorithm === 'gronsfeld' && (
  <div className="space-y-2">
    <Label>Key (numbers only)</Label>
    <Input
      value={vigenereKey}
      onChange={(e) => setVigenereKey(e.target.value.replace(/[^0-9]/g, ''))}
      placeholder="Enter numeric key..."
      className="input-ring"
    />
  </div>
)}

{selectedAlgorithm === 'beaufort' && (
  <div className="space-y-2">
    <Label>Key (text)</Label>
    <Input
      value={vigenereKey}
      onChange={(e) => setVigenereKey(e.target.value)}
      placeholder="Enter key..."
      className="input-ring"
    />
  </div>
)}

{selectedAlgorithm === 'autokey' && (
  <div className="space-y-2">
    <Label>Key (text)</Label>
    <Input
      value={vigenereKey}
      onChange={(e) => setVigenereKey(e.target.value)}
      placeholder="Enter key..."
      className="input-ring"
    />
  </div>
)}

{selectedAlgorithm === 'running' && (
  <div className="space-y-2">
    <Label>Key (text)</Label>
    <Input
      value={vigenereKey}
      onChange={(e) => setVigenereKey(e.target.value)}
      placeholder="Enter key..."
      className="input-ring"
    />
  </div>
)}

{selectedAlgorithm === 'hill' && (
  <div className="space-y-2">
    <Label>Matrix (2x2, determinant must be coprime with 26)</Label>
    <div className="grid grid-cols-2 gap-2">
      <Input
        type="number"
        value={hillMatrix[0][0]}
        onChange={(e) => setHillMatrix([
          [parseInt(e.target.value) || 0, hillMatrix[0][1]],
          [hillMatrix[1][0], hillMatrix[1][1]]
        ])}
        className="input-ring"
      />
      <Input
        type="number"
        value={hillMatrix[0][1]}
        onChange={(e) => setHillMatrix([
          [hillMatrix[0][0], parseInt(e.target.value) || 0],
          [hillMatrix[1][0], hillMatrix[1][1]]
        ])}
        className="input-ring"
      />
      <Input
        type="number"
        value={hillMatrix[1][0]}
        onChange={(e) => setHillMatrix([
          [hillMatrix[0][0], hillMatrix[0][1]],
          [parseInt(e.target.value) || 0, hillMatrix[1][1]]
        ])}
        className="input-ring"
      />
      <Input
        type="number"
        value={hillMatrix[1][1]}
        onChange={(e) => setHillMatrix([
          [hillMatrix[0][0], hillMatrix[0][1]],
          [hillMatrix[1][0], parseInt(e.target.value) || 0]
        ])}
        className="input-ring"
      />
    </div>
  </div>
)}

{selectedAlgorithm === 'columnar' && (
  <div className="space-y-2">
    <Label>Key (numbers only)</Label>
    <Input
      value={vigenereKey}
      onChange={(e) => setVigenereKey(e.target.value.replace(/[^0-9]/g, ''))}
      placeholder="Enter numeric key..."
      className="input-ring"
    />
  </div>
)}

{selectedAlgorithm === 'double' && (
  <>
    <div className="space-y-2">
      <Label>First Key (numbers only)</Label>
      <Input
        value={doubleTranspositionKey1}
        onChange={(e) => setDoubleTranspositionKey1(e.target.value.replace(/[^0-9]/g, ''))}
        placeholder="Enter first numeric key..."
        className="input-ring"
      />
    </div>
    <div className="space-y-2">
      <Label>Second Key (numbers only)</Label>
      <Input
        value={doubleTranspositionKey2}
        onChange={(e) => setDoubleTranspositionKey2(e.target.value.replace(/[^0-9]/g, ''))}
        placeholder="Enter second numeric key..."
        className="input-ring"
      />
    </div>
  </>
)}

{selectedAlgorithm === 'myszkowski' && (
  <div className="space-y-2">
    <Label>Key (text)</Label>
    <Input
      value={vigenereKey}
      onChange={(e) => setVigenereKey(e.target.value)}
      placeholder="Enter key..."
      className="input-ring"
    />
  </div>
)}

{selectedAlgorithm === 'grilles' && (
  <div className="space-y-2">
    <Label>Grille Pattern (1=hole, 0=solid)</Label>
    <Textarea
      value={grillePattern}
      onChange={(e) => setGrillePattern(e.target.value)}
      placeholder="Enter grille pattern (e.g., 1000\n0001\n0010\n0100)"
      className="min-h-[100px] input-ring"
    />
  </div>
)}

                  <Button 
                    onClick={processText}
                    className="w-full button-glow"
                    disabled={!inputText}
                  >
                    <Wand2 className="h-4 w-4 mr-2" />
                    Process Text
                  </Button>

                  <div className="mt-6">
                    <div className="flex justify-between items-center mb-2">
                      <h3 className="text-lg font-medium text-gray-800">Result</h3>
                      <div className="flex items-center gap-2">
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={swapTexts}
                                disabled={!outputText}
                                className="button-glow"
                              >
                                <RefreshCw className="h-4 w-4" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Swap input/output</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button 
                                variant="outline" 
                                size="sm" 
                                onClick={copyToClipboard}
                                disabled={!outputText}
                                className="button-glow"
                              >
                                {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>Copy to clipboard</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      </div>
                    </div>
                    
                    {error ? (
                      <Alert variant="destructive" className="bg-red-50 border-red-200 text-red-800">
                        <AlertCircle className="h-4 w-4" />
                        <AlertTitle>Error</AlertTitle>
                        <AlertDescription>{error}</AlertDescription>
                      </Alert>
                    ) : (
                      <div className="relative">
                        <Textarea 
                          value={outputText}
                          readOnly
                          className="min-h-[100px] input-ring"
                          placeholder="Result will appear here..."
                        />
                        {outputText && (
                          <Badge className={`absolute top-2 right-2 ${isEncrypting ? 'bg-green-500' : 'bg-amber-500'}`}>
                            {isEncrypting ? 'Encrypted' : 'Decrypted'}
                          </Badge>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="mt-4">
                    <div className="flex items-center space-x-2">
                      <Switch 
                        id="show-steps"
                        checked={showSteps}
                        onCheckedChange={setShowSteps}
                        className="data-[state=checked]:bg-blue-500"
                      />
                      <Label htmlFor="show-steps" className="cursor-pointer flex items-center gap-1 text-gray-700">
                        <Info className="h-4 w-4 text-blue-600" /> 
                        Show encryption/decryption steps
                      </Label>
                    </div>
                    
                    {showSteps && steps.length > 0 && (
                      <div className="mt-4">
                        <ScrollArea className="h-[200px] rounded-md border border-blue-100 p-4 bg-blue-50/30">
                          <div className="space-y-2">
                            {steps.map((step, index) => (
                              <React.Fragment key={index}>
                                <p className="text-sm text-gray-600">{step}</p>
                                {index < steps.length - 1 && <Separator className="bg-blue-100" />}
                              </React.Fragment>
                            ))}
                          </div>
                        </ScrollArea>
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <footer className="mt-12 text-center">
            <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-white/80 backdrop-blur-sm border border-blue-100 shadow-sm hover:shadow-md transition-all duration-300">
              <a 
                href="https://github.com/rishithr1/CryptoGraphy-13-Algorithms" 
                target="_blank" 
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 text-gray-600 hover:text-blue-600 transition-colors"
              >
                <Github className="h-4 w-4" />
                Made by V S Rishith Reddy
              </a>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}

export default App;
