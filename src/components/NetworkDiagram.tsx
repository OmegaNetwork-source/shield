import React, { useCallback, useState, useRef, useEffect } from 'react';
import ReactFlow, {
    Node,
    Edge,
    addEdge,
    Connection,
    useNodesState,
    useEdgesState,
    Controls,
    MiniMap,
    Background,
    BackgroundVariant,
    Panel,
    NodeTypes,
    Handle,
    Position,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { 
    Server, 
    Shield, 
    Router, 
    Network, 
    Cloud, 
    Database, 
    Save, 
    Download, 
    Trash2, 
    FileText,
    X,
    Square,
    AlignLeft,
    Edit2,
    Check,
    Type
} from 'lucide-react';

// Editable Node Component (base for all nodes)
function EditableNode({ data, id, type, children }: { data: any; id: string; type: string; children: React.ReactNode }) {
    const [isEditing, setIsEditing] = useState(false);
    const [editValue, setEditValue] = useState(data.label || '');
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (isEditing && inputRef.current) {
            inputRef.current.focus();
            inputRef.current.select();
        }
    }, [isEditing]);

    const handleSave = () => {
        data.label = editValue;
        setIsEditing(false);
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter') {
            handleSave();
        } else if (e.key === 'Escape') {
            setEditValue(data.label || '');
            setIsEditing(false);
        }
    };

    return (
        <div className="relative">
            {children}
            <div className="absolute -top-6 left-0 right-0 flex items-center justify-center">
                {isEditing ? (
                    <input
                        ref={inputRef}
                        type="text"
                        value={editValue}
                        onChange={(e) => setEditValue(e.target.value)}
                        onBlur={handleSave}
                        onKeyDown={handleKeyDown}
                        className="px-2 py-0.5 text-xs border border-blue-500 rounded bg-white shadow-md min-w-[80px] max-w-[200px]"
                        onClick={(e) => e.stopPropagation()}
                    />
                ) : (
                    <div 
                        className="flex items-center gap-1 px-2 py-0.5 bg-white/90 rounded shadow-sm cursor-pointer hover:bg-white group"
                        onClick={(e) => {
                            e.stopPropagation();
                            setIsEditing(true);
                        }}
                    >
                        <span className="text-xs font-medium text-gray-700">{data.label || `${type} ${id}`}</span>
                        <Edit2 size={10} className="text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                )}
            </div>
            <Handle type="target" position={Position.Top} />
            <Handle type="source" position={Position.Bottom} />
            <Handle type="target" position={Position.Left} />
            <Handle type="source" position={Position.Right} />
        </div>
    );
}

// Server Node Component
function ServerNode({ data, id }: { data: any; id: string }) {
    return (
        <EditableNode data={data} id={id} type="Server">
            <div className="px-4 py-3 bg-blue-50 border-2 border-blue-300 rounded-lg shadow-md min-w-[120px]">
                <div className="flex items-center gap-2 mb-1">
                    <Server size={16} className="text-blue-600" />
                    <span className="font-semibold text-blue-900 text-sm">Server</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Firewall Node Component
function FirewallNode({ data, id }: { data: any; id: string }) {
    return (
        <EditableNode data={data} id={id} type="Firewall">
            <div className="px-4 py-3 bg-red-50 border-2 border-red-300 rounded-lg shadow-md min-w-[120px]">
                <div className="flex items-center gap-2 mb-1">
                    <Shield size={16} className="text-red-600" />
                    <span className="font-semibold text-red-900 text-sm">Firewall</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Router Node Component
function RouterNode({ data, id }: { data: any; id: string }) {
    return (
        <EditableNode data={data} id={id} type="Router">
            <div className="px-4 py-3 bg-green-50 border-2 border-green-300 rounded-lg shadow-md min-w-[120px]">
                <div className="flex items-center gap-2 mb-1">
                    <Router size={16} className="text-green-600" />
                    <span className="font-semibold text-green-900 text-sm">Router</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Switch Node Component
function SwitchNode({ data, id }: { data: any; id: string }) {
    return (
        <EditableNode data={data} id={id} type="Switch">
            <div className="px-4 py-3 bg-purple-50 border-2 border-purple-300 rounded-lg shadow-md min-w-[120px]">
                <div className="flex items-center gap-2 mb-1">
                    <Network size={16} className="text-purple-600" />
                    <span className="font-semibold text-purple-900 text-sm">Switch</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Cloud Node Component
function CloudNode({ data, id }: { data: any; id: string }) {
    return (
        <EditableNode data={data} id={id} type="Cloud">
            <div className="px-4 py-3 bg-cyan-50 border-2 border-cyan-300 rounded-lg shadow-md min-w-[120px]">
                <div className="flex items-center gap-2 mb-1">
                    <Cloud size={16} className="text-cyan-600" />
                    <span className="font-semibold text-cyan-900 text-sm">Cloud</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Database Node Component
function DatabaseNode({ data, id }: { data: any; id: string }) {
    return (
        <EditableNode data={data} id={id} type="Database">
            <div className="px-4 py-3 bg-orange-50 border-2 border-orange-300 rounded-lg shadow-md min-w-[120px]">
                <div className="flex items-center gap-2 mb-1">
                    <Database size={16} className="text-orange-600" />
                    <span className="font-semibold text-orange-900 text-sm">Database</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Text Box Node Component
function TextBoxNode({ data, id }: { data: any; id: string }) {
    const [isEditing, setIsEditing] = useState(false);
    const [text, setText] = useState(data.text || 'Text Box');
    const textareaRef = useRef<HTMLTextAreaElement>(null);

    useEffect(() => {
        if (isEditing && textareaRef.current) {
            textareaRef.current.focus();
        }
    }, [isEditing]);

    const handleSave = () => {
        data.text = text;
        setIsEditing(false);
    };

    return (
        <div className="px-4 py-3 bg-yellow-50 border-2 border-yellow-300 rounded-lg shadow-md min-w-[150px] min-h-[80px]">
            {isEditing ? (
                <textarea
                    ref={textareaRef}
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    onBlur={handleSave}
                    onKeyDown={(e) => {
                        if (e.key === 'Escape') {
                            setText(data.text || 'Text Box');
                            setIsEditing(false);
                        }
                    }}
                    className="w-full h-full resize-none border-none bg-transparent text-sm text-gray-700 outline-none"
                    onClick={(e) => e.stopPropagation()}
                />
            ) : (
                <div 
                    className="w-full h-full cursor-text text-sm text-gray-700 whitespace-pre-wrap"
                    onClick={() => setIsEditing(true)}
                >
                    {text || 'Double-click to edit'}
                </div>
            )}
        </div>
    );
}

// Boundary/Group Node Component
function BoundaryNode({ data, id }: { data: any; id: string }) {
    const [isEditing, setIsEditing] = useState(false);
    const [label, setLabel] = useState(data.label || 'Boundary');
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (isEditing && inputRef.current) {
            inputRef.current.focus();
            inputRef.current.select();
        }
    }, [isEditing]);

    const handleSave = () => {
        data.label = label;
        setIsEditing(false);
    };

    return (
        <div className="relative" style={{ width: data.width || 400, height: data.height || 300 }}>
            <div className="absolute inset-0 border-4 border-dashed border-gray-400 rounded-lg bg-gray-50/30">
                {isEditing ? (
                    <input
                        ref={inputRef}
                        type="text"
                        value={label}
                        onChange={(e) => setLabel(e.target.value)}
                        onBlur={handleSave}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSave();
                            if (e.key === 'Escape') {
                                setLabel(data.label || 'Boundary');
                                setIsEditing(false);
                            }
                        }}
                        className="absolute top-2 left-2 px-2 py-1 text-sm font-semibold border border-blue-500 rounded bg-white shadow-md"
                        onClick={(e) => e.stopPropagation()}
                    />
                ) : (
                    <div 
                        className="absolute top-2 left-2 px-2 py-1 text-sm font-semibold text-gray-700 bg-white/90 rounded cursor-pointer hover:bg-white"
                        onClick={(e) => {
                            e.stopPropagation();
                            setIsEditing(true);
                        }}
                    >
                        {label}
                    </div>
                )}
            </div>
        </div>
    );
}

// Custom node types
const nodeTypes: NodeTypes = {
    server: ServerNode,
    firewall: FirewallNode,
    router: RouterNode,
    switch: SwitchNode,
    cloud: CloudNode,
    database: DatabaseNode,
    textbox: TextBoxNode,
    boundary: BoundaryNode,
};

interface NetworkDiagramProps {
    darkMode?: boolean;
}

export default function NetworkDiagram({ darkMode = false }: NetworkDiagramProps) {
    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);
    const [diagramName, setDiagramName] = useState('Untitled Diagram');
    const [showSaveModal, setShowSaveModal] = useState(false);
    const [savedDiagrams, setSavedDiagrams] = useState<any[]>([]);
    const [selectedDiagram, setSelectedDiagram] = useState<string | null>(null);
    const reactFlowWrapper = useRef<HTMLDivElement>(null);
    const [reactFlowInstance, setReactFlowInstance] = useState<any>(null);
    const [nodeCounter, setNodeCounter] = useState<Record<string, number>>({});

    // Load saved diagrams on mount
    useEffect(() => {
        loadSavedDiagrams();
    }, []);

    const loadSavedDiagrams = () => {
        try {
            const saved = localStorage.getItem('networkDiagrams');
            if (saved) {
                const diagrams = JSON.parse(saved);
                setSavedDiagrams(diagrams);
            }
        } catch (e) {
            console.error('Failed to load saved diagrams:', e);
        }
    };

    const onConnect = useCallback(
        (params: Connection) => {
            // Make connections visible with arrows
            setEdges((eds) => addEdge({ ...params, animated: true, style: { strokeWidth: 2 } }, eds));
        },
        [setEdges]
    );

    const onDragOver = useCallback((event: React.DragEvent) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'move';
    }, []);

    const onDrop = useCallback(
        (event: React.DragEvent) => {
            event.preventDefault();

            const type = event.dataTransfer.getData('application/reactflow');
            if (!type || !reactFlowInstance || !reactFlowWrapper.current) {
                return;
            }

            const reactFlowBounds = reactFlowWrapper.current.getBoundingClientRect();
            const position = reactFlowInstance.project({
                x: event.clientX - reactFlowBounds.left,
                y: event.clientY - reactFlowBounds.top,
            });

            const count = (nodeCounter[type] || 0) + 1;
            setNodeCounter(prev => ({ ...prev, [type]: count }));

            const newNode: Node = {
                id: `${type}-${Date.now()}`,
                type,
                position,
                data: { label: '' }, // Start with empty label so user can edit
            };

            setNodes((nds) => nds.concat(newNode));
        },
        [reactFlowInstance, nodeCounter, setNodes]
    );

    const autoAlign = useCallback(() => {
        if (nodes.length === 0) return;

        const cols = Math.ceil(Math.sqrt(nodes.length));
        const spacing = 200;
        const startX = 100;
        const startY = 100;

        const alignedNodes = nodes.map((node, index) => {
            const row = Math.floor(index / cols);
            const col = index % cols;
            return {
                ...node,
                position: {
                    x: startX + col * spacing,
                    y: startY + row * spacing,
                },
            };
        });

        setNodes(alignedNodes);
    }, [nodes, setNodes]);

    const saveDiagram = () => {
        const diagramData = {
            id: selectedDiagram || `diagram-${Date.now()}`,
            name: diagramName,
            nodes,
            edges,
            createdAt: selectedDiagram ? savedDiagrams.find(d => d.id === selectedDiagram)?.createdAt : new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };

        const updated = selectedDiagram
            ? savedDiagrams.map(d => d.id === selectedDiagram ? diagramData : d)
            : [...savedDiagrams, diagramData];

        localStorage.setItem('networkDiagrams', JSON.stringify(updated));
        setSavedDiagrams(updated);
        setShowSaveModal(false);
        setSelectedDiagram(diagramData.id);
    };

    const loadDiagram = (diagramId: string) => {
        const diagram = savedDiagrams.find(d => d.id === diagramId);
        if (diagram) {
            setNodes(diagram.nodes || []);
            setEdges(diagram.edges || []);
            setDiagramName(diagram.name);
            setSelectedDiagram(diagramId);
        }
    };

    const deleteDiagram = (diagramId: string) => {
        if (window.confirm('Are you sure you want to delete this diagram?')) {
            const updated = savedDiagrams.filter(d => d.id !== diagramId);
            localStorage.setItem('networkDiagrams', JSON.stringify(updated));
            setSavedDiagrams(updated);
            if (selectedDiagram === diagramId) {
                setNodes([]);
                setEdges([]);
                setDiagramName('Untitled Diagram');
                setSelectedDiagram(null);
            }
        }
    };

    const exportToPNG = async () => {
        if (!reactFlowInstance) return;
        alert('PNG export: Use browser screenshot (F12 > Screenshot) or right-click > Print > Save as PDF');
    };

    const clearDiagram = () => {
        if (window.confirm('Clear the current diagram? This cannot be undone.')) {
            setNodes([]);
            setEdges([]);
            setSelectedDiagram(null);
            setDiagramName('Untitled Diagram');
            setNodeCounter({});
        }
    };

    return (
        <div className="flex h-full">
            {/* Left Sidebar - Device Palette (narrower) */}
            <div className={`w-48 border-r ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-gray-50 border-gray-200'} p-3 overflow-y-auto`}>
                <h3 className={`font-semibold mb-3 text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Devices</h3>
                <p className={`text-xs mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Drag to canvas
                </p>

                <div className="space-y-2 mb-6">
                    {[
                        { type: 'server', icon: Server, label: 'Server', color: 'blue' },
                        { type: 'firewall', icon: Shield, label: 'Firewall', color: 'red' },
                        { type: 'router', icon: Router, label: 'Router', color: 'green' },
                        { type: 'switch', icon: Network, label: 'Switch', color: 'purple' },
                        { type: 'cloud', icon: Cloud, label: 'Cloud', color: 'cyan' },
                        { type: 'database', icon: Database, label: 'Database', color: 'orange' },
                        { type: 'textbox', icon: Type, label: 'Text Box', color: 'yellow' },
                        { type: 'boundary', icon: Square, label: 'Boundary', color: 'gray' },
                    ].map((device) => {
                        const Icon = device.icon;
                        return (
                            <div
                                key={device.type}
                                draggable
                                onDragStart={(e) => e.dataTransfer.setData('application/reactflow', device.type)}
                                className={`p-2 border-2 border-dashed rounded-lg cursor-move transition-all hover:shadow-md text-xs ${
                                    darkMode 
                                        ? 'border-gray-600 bg-gray-700 hover:border-gray-500' 
                                        : 'border-gray-300 bg-white hover:border-gray-400'
                                }`}
                            >
                                <div className="flex items-center gap-2">
                                    <Icon size={14} className={`text-${device.color}-600`} />
                                    <span className={`font-medium ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                                        {device.label}
                                    </span>
                                </div>
                            </div>
                        );
                    })}
                </div>

                <div className="pt-4 border-t border-gray-300">
                    <h4 className={`font-semibold mb-2 text-xs ${darkMode ? 'text-white' : 'text-gray-900'}`}>Saved</h4>
                    <div className="space-y-1 max-h-64 overflow-y-auto">
                        {savedDiagrams.map((diagram) => (
                            <div
                                key={diagram.id}
                                className={`p-2 rounded border cursor-pointer transition-all text-xs ${
                                    selectedDiagram === diagram.id
                                        ? darkMode ? 'bg-blue-900 border-blue-600' : 'bg-blue-50 border-blue-300'
                                        : darkMode ? 'bg-gray-700 border-gray-600 hover:bg-gray-600' : 'bg-white border-gray-200 hover:bg-gray-50'
                                }`}
                                onClick={() => loadDiagram(diagram.id)}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex-1 min-w-0">
                                        <div className={`font-medium truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                            {diagram.name}
                                        </div>
                                        <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                            {new Date(diagram.updatedAt).toLocaleDateString()}
                                        </div>
                                    </div>
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            deleteDiagram(diagram.id);
                                        }}
                                        className="p-0.5 hover:bg-red-500 rounded text-gray-400 hover:text-white ml-1"
                                    >
                                        <Trash2 size={10} />
                                    </button>
                                </div>
                            </div>
                        ))}
                        {savedDiagrams.length === 0 && (
                            <p className={`text-xs text-center py-2 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                No saved diagrams
                            </p>
                        )}
                    </div>
                </div>
            </div>

            {/* Main Canvas Area (wider) */}
            <div className="flex-1 flex flex-col min-w-0">
                {/* Toolbar */}
                <div className={`border-b p-2 flex items-center justify-between ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                    <div className="flex items-center gap-2">
                        <input
                            type="text"
                            value={diagramName}
                            onChange={(e) => setDiagramName(e.target.value)}
                            className={`px-3 py-1 border rounded-lg text-sm font-medium ${
                                darkMode 
                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                    : 'bg-white border-gray-300 text-gray-900'
                            }`}
                            placeholder="Diagram Name"
                        />
                        <button
                            onClick={() => setShowSaveModal(true)}
                            className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                        >
                            <Save size={14} /> Save
                        </button>
                        <button
                            onClick={autoAlign}
                            className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                            title="Auto-align all nodes"
                        >
                            <AlignLeft size={14} /> Align
                        </button>
                        <button
                            onClick={exportToPNG}
                            className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                        >
                            <Download size={14} /> Export
                        </button>
                        <button
                            onClick={clearDiagram}
                            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                        >
                            <Trash2 size={14} /> Clear
                        </button>
                    </div>
                </div>

                {/* React Flow Canvas */}
                <div ref={reactFlowWrapper} className="flex-1" style={{ background: darkMode ? '#1f2937' : '#f9fafb' }}>
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onConnect={onConnect}
                        onInit={setReactFlowInstance}
                        onDrop={onDrop}
                        onDragOver={onDragOver}
                        nodeTypes={nodeTypes}
                        fitView
                        connectionLineStyle={{ strokeWidth: 2 }}
                        defaultEdgeOptions={{ 
                            animated: true,
                            style: { strokeWidth: 2 },
                            type: 'smoothstep'
                        }}
                    >
                        <Controls />
                        <MiniMap 
                            nodeColor={(node) => {
                                if (node.type === 'firewall') return '#ef4444';
                                if (node.type === 'server') return '#3b82f6';
                                if (node.type === 'router') return '#10b981';
                                if (node.type === 'switch') return '#a855f7';
                                if (node.type === 'cloud') return '#06b6d4';
                                if (node.type === 'database') return '#f97316';
                                if (node.type === 'textbox') return '#eab308';
                                if (node.type === 'boundary') return '#6b7280';
                                return '#6b7280';
                            }}
                        />
                        <Background variant={BackgroundVariant.Dots} gap={12} size={1} />
                        <Panel position="top-right" className={`${darkMode ? 'text-white' : 'text-gray-700'}`}>
                            <div className="text-xs bg-white/90 px-2 py-1 rounded shadow">
                                {nodes.length} nodes, {edges.length} connections
                            </div>
                        </Panel>
                    </ReactFlow>
                </div>
            </div>

            {/* Save Modal */}
            {showSaveModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-white rounded-xl shadow-2xl max-w-md w-full mx-4">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100 flex items-center justify-between">
                            <h3 className="text-lg font-semibold text-gray-900">Save Diagram</h3>
                            <button onClick={() => setShowSaveModal(false)} className="text-gray-400 hover:text-gray-600">
                                <X size={20} />
                            </button>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className="block text-sm font-medium text-gray-700 mb-2">Diagram Name</label>
                                <input
                                    type="text"
                                    value={diagramName}
                                    onChange={(e) => setDiagramName(e.target.value)}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                                    placeholder="Enter diagram name"
                                />
                            </div>
                            <div className="flex justify-end gap-3">
                                <button
                                    onClick={() => setShowSaveModal(false)}
                                    className="px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-800"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={saveDiagram}
                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg"
                                >
                                    Save
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
