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
    NodeResizer,
    useReactFlow,
    EdgeLabelRenderer,
    BaseEdge,
    getBezierPath,
    EdgeProps,
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
    Type,
    Maximize2,
    Minimize2,
    Monitor,
    ShieldCheck,
    Laptop,
    Printer,
    Radio,
    Activity,
    Lock,
    User,
    Package,
    Minus,
    Bold,
    List,
    Italic,
    AlignCenter,
    AlignRight,
    Minus as MinusIcon,
    Plus,
    Copy,
    FileSpreadsheet,
    HardDrive
} from 'lucide-react';
import JSZip from 'jszip';

// Editable Node Component (base for all nodes)
function EditableNode({ data, id, type, children, selected, onDelete }: { data: any; id: string; type: string; children: React.ReactNode; selected?: boolean; onDelete?: () => void }) {
    const [isEditing, setIsEditing] = useState(false);
    const [editValue, setEditValue] = useState(data.label || 'text');
    const inputRef = useRef<HTMLInputElement>(null);
    const { getNodes, setNodes } = useReactFlow();

    useEffect(() => {
        if (isEditing && inputRef.current) {
            inputRef.current.focus();
            inputRef.current.select();
        }
    }, [isEditing]);

    // Initialize label to "text" if not set
    useEffect(() => {
        if (!data.label) {
            data.label = 'text';
            setEditValue('text');
        }
    }, []);

    const handleSave = () => {
        data.label = editValue || 'text';
        setIsEditing(false);
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter') {
            handleSave();
        } else if (e.key === 'Escape') {
            setEditValue(data.label || 'text');
            setIsEditing(false);
        }
    };

    const handleResize = (_event: any, { width, height }: { width: number; height: number }) => {
        setNodes((nds) => 
            nds.map((node) => 
                node.id === id 
                    ? { ...node, width, height, data: { ...node.data, width, height } }
                    : node
            )
        );
        data.width = width;
        data.height = height;
    };

    const containerStyle = {
        width: data.width || 'auto',
        height: data.height || 'auto',
        minWidth: data.width ? undefined : 120,
        minHeight: data.height ? undefined : 60,
    };

    return (
        <div className="relative group" style={containerStyle}>
            <NodeResizer 
                color="#3b82f6" 
                isVisible={selected}
                minWidth={100}
                minHeight={60}
                onResize={handleResize}
            />
            {selected && onDelete && (
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        e.preventDefault();
                        onDelete();
                    }}
                    className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-1 shadow-lg z-10"
                    title="Delete"
                >
                    <X size={12} />
                </button>
            )}
            <div className="w-full h-full">
                {children}
            </div>
            <div className="absolute -top-8 left-0 right-0 flex items-center justify-center pointer-events-none">
                {isEditing ? (
                    <input
                        ref={inputRef}
                        type="text"
                        value={editValue}
                        onChange={(e) => setEditValue(e.target.value)}
                        onBlur={handleSave}
                        onKeyDown={handleKeyDown}
                        className="px-1.5 py-0.5 text-xs border border-blue-500 rounded bg-white shadow-md w-16 pointer-events-auto"
                        onClick={(e) => {
                            e.stopPropagation();
                            e.preventDefault();
                        }}
                        onMouseDown={(e) => {
                            e.stopPropagation();
                            e.preventDefault();
                        }}
                        onDoubleClick={(e) => {
                            e.stopPropagation();
                            e.preventDefault();
                        }}
                    />
                ) : (
                    <div 
                        className="px-1.5 py-0.5 bg-white/90 rounded shadow-sm cursor-text pointer-events-auto"
                        onClick={(e) => {
                            e.stopPropagation();
                            e.preventDefault();
                            setIsEditing(true);
                        }}
                        onMouseDown={(e) => {
                            e.stopPropagation();
                            e.preventDefault();
                        }}
                    >
                        <span className="text-xs font-medium text-gray-700">{data.label || 'text'}</span>
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
function ServerNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Server" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-blue-50 border-2 border-blue-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Server size={16} className="text-blue-600" />
                    <span className="font-semibold text-blue-900 text-sm">Server</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Firewall Node Component
function FirewallNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Firewall" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-red-50 border-2 border-red-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Shield size={16} className="text-red-600" />
                    <span className="font-semibold text-red-900 text-sm">Firewall</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Router Node Component
function RouterNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Router" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-green-50 border-2 border-green-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Router size={16} className="text-green-600" />
                    <span className="font-semibold text-green-900 text-sm">Router</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Switch Node Component
function SwitchNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Switch" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-purple-50 border-2 border-purple-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Network size={16} className="text-purple-600" />
                    <span className="font-semibold text-purple-900 text-sm">Switch</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Cloud Node Component
function CloudNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Cloud" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-cyan-50 border-2 border-cyan-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Cloud size={16} className="text-cyan-600" />
                    <span className="font-semibold text-cyan-900 text-sm">Cloud</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Database Node Component
function DatabaseNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Database" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-orange-50 border-2 border-orange-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Database size={16} className="text-orange-600" />
                    <span className="font-semibold text-orange-900 text-sm">Database</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Text Box Node Component
function TextBoxNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    const [isEditing, setIsEditing] = useState(false);
    const [text, setText] = useState(data.text || 'Text Box');
    const [fontSize, setFontSize] = useState(data.fontSize || 14);
    const [isBold, setIsBold] = useState(data.isBold || false);
    const [isItalic, setIsItalic] = useState(data.isItalic || false);
    const [textAlign, setTextAlign] = useState(data.textAlign || 'left');
    const textareaRef = useRef<HTMLTextAreaElement>(null);
    const contentRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (isEditing && textareaRef.current) {
            textareaRef.current.focus();
        }
    }, [isEditing]);

    // Initialize data properties
    useEffect(() => {
        if (!data.fontSize) data.fontSize = 14;
        if (data.isBold === undefined) data.isBold = false;
        if (data.isItalic === undefined) data.isItalic = false;
        if (!data.textAlign) data.textAlign = 'left';
    }, []);

    const handleSave = () => {
        data.text = text;
        data.fontSize = fontSize;
        data.isBold = isBold;
        data.isItalic = isItalic;
        data.textAlign = textAlign;
        setIsEditing(false);
    };

    const toggleBold = () => {
        setIsBold(!isBold);
    };

    const toggleItalic = () => {
        setIsItalic(!isItalic);
    };

    const applyTextAlign = (align: 'left' | 'center' | 'right') => {
        setTextAlign(align);
    };

    const increaseFontSize = () => {
        setFontSize((prev: number) => Math.min(prev + 2, 48));
    };

    const decreaseFontSize = () => {
        setFontSize((prev: number) => Math.max(prev - 2, 8));
    };

    const textStyle = {
        fontSize: `${fontSize}px`,
        fontWeight: isBold ? 'bold' : 'normal',
        fontStyle: isItalic ? 'italic' : 'normal',
        textAlign: textAlign as 'left' | 'center' | 'right',
    };

    const { setNodes } = useReactFlow();

    const handleResize = (_event: any, { width, height }: { width: number; height: number }) => {
        setNodes((nds) => 
            nds.map((node) => 
                node.id === id 
                    ? { ...node, width, height, data: { ...node.data, width, height } }
                    : node
            )
        );
        data.width = width;
        data.height = height;
    };

    return (
        <div className="relative group" style={{ width: data.width || 150, height: data.height || 80 }}>
            <NodeResizer 
                color="#3b82f6" 
                isVisible={selected}
                minWidth={150}
                minHeight={80}
                onResize={handleResize}
            />
            {selected && (
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        e.preventDefault();
                        handleDelete();
                    }}
                    className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-1 shadow-lg z-10"
                    title="Delete"
                >
                    <X size={12} />
                </button>
            )}
            <div className="px-4 py-3 bg-gray-100 border-2 border-gray-300 rounded-lg shadow-md w-full h-full">
                {isEditing ? (
                    <div className="w-full h-full">
                        {/* Formatting Toolbar */}
                        <div 
                            className="formatting-toolbar mb-2 flex items-center gap-1 p-1 bg-white rounded border border-gray-300 flex-wrap"
                            onClick={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                            }}
                            onMouseDown={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                            }}
                        >
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    decreaseFontSize();
                                }}
                                className="p-1 hover:bg-gray-100 rounded"
                                title="Decrease font size"
                                type="button"
                            >
                                <MinusIcon size={14} />
                            </button>
                            <span className="text-xs px-1">{fontSize}px</span>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    increaseFontSize();
                                }}
                                className="p-1 hover:bg-gray-100 rounded"
                                title="Increase font size"
                                type="button"
                            >
                                <Plus size={14} />
                            </button>
                            <div className="w-px h-4 bg-gray-300 mx-1"></div>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    toggleBold();
                                }}
                                className={`p-1 rounded ${isBold ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
                                title="Bold"
                                type="button"
                            >
                                <Bold size={14} />
                            </button>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    toggleItalic();
                                }}
                                className={`p-1 rounded ${isItalic ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
                                title="Italic"
                                type="button"
                            >
                                <Italic size={14} />
                            </button>
                            <div className="w-px h-4 bg-gray-300 mx-1"></div>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    applyTextAlign('left');
                                }}
                                className={`p-1 rounded ${textAlign === 'left' ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
                                title="Align left"
                                type="button"
                            >
                                <AlignLeft size={14} />
                            </button>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    applyTextAlign('center');
                                }}
                                className={`p-1 rounded ${textAlign === 'center' ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
                                title="Align center"
                                type="button"
                            >
                                <AlignCenter size={14} />
                            </button>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    e.preventDefault();
                                    applyTextAlign('right');
                                }}
                                className={`p-1 rounded ${textAlign === 'right' ? 'bg-blue-100' : 'hover:bg-gray-100'}`}
                                title="Align right"
                                type="button"
                            >
                                <AlignRight size={14} />
                            </button>
                        </div>
                        <textarea
                            ref={textareaRef}
                            value={text}
                            onChange={(e) => setText(e.target.value)}
                            onBlur={(e) => {
                                // Don't blur if clicking on toolbar buttons
                                const relatedTarget = e.relatedTarget as HTMLElement;
                                if (!relatedTarget || !relatedTarget.closest('.formatting-toolbar')) {
                                    handleSave();
                                }
                            }}
                            onKeyDown={(e) => {
                                if (e.key === 'Escape') {
                                    setText(data.text || 'Text Box');
                                    setFontSize(data.fontSize || 14);
                                    setIsBold(data.isBold || false);
                                    setIsItalic(data.isItalic || false);
                                    setTextAlign(data.textAlign || 'left');
                                    setIsEditing(false);
                                }
                            }}
                            style={textStyle}
                            className="w-full h-full resize-none border-none bg-transparent text-gray-700 outline-none select-text"
                            onClick={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                            }}
                            onMouseDown={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                            }}
                        />
                    </div>
                ) : (
                    <div 
                        ref={contentRef}
                        className="w-full h-full cursor-text text-gray-700 whitespace-pre-wrap select-text"
                        style={textStyle}
                        onClick={() => setIsEditing(true)}
                    >
                        {text || 'Double-click to edit'}
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

// Desktop Node Component
function DesktopNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Desktop" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-indigo-50 border-2 border-indigo-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Monitor size={16} className="text-indigo-600" />
                    <span className="font-semibold text-indigo-900 text-sm">Desktop</span>
                </div>
            </div>
        </EditableNode>
    );
}

// IDS/IDP Node Component
function IdsIdpNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="IDS/IDP" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-pink-50 border-2 border-pink-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <ShieldCheck size={16} className="text-pink-600" />
                    <span className="font-semibold text-pink-900 text-sm">IDS/IDP</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Laptop Node Component
function LaptopNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Laptop" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-teal-50 border-2 border-teal-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Laptop size={16} className="text-teal-600" />
                    <span className="font-semibold text-teal-900 text-sm">Laptop</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Load Balancer Node Component
function LoadBalancerNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Load Balancer" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-amber-50 border-2 border-amber-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Activity size={16} className="text-amber-600" />
                    <span className="font-semibold text-amber-900 text-sm">Load Balancer</span>
                </div>
            </div>
        </EditableNode>
    );
}

// VPN Gateway Node Component
function VpnGatewayNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="VPN Gateway" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-slate-50 border-2 border-slate-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Lock size={16} className="text-slate-600" />
                    <span className="font-semibold text-slate-900 text-sm">VPN Gateway</span>
                </div>
            </div>
        </EditableNode>
    );
}

// WAP (Wireless Access Point) Node Component
function WapNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="WAP" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-emerald-50 border-2 border-emerald-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Radio size={16} className="text-emerald-600" />
                    <span className="font-semibold text-emerald-900 text-sm">WAP</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Printer Node Component
function PrinterNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Printer" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-rose-50 border-2 border-rose-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <Printer size={16} className="text-rose-600" />
                    <span className="font-semibold text-rose-900 text-sm">Printer</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Personal Box Node Component
function PersonalBoxNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Personal Box" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-violet-50 border-2 border-violet-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <User size={16} className="text-violet-600" />
                    <span className="font-semibold text-violet-900 text-sm">Personal Box</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Dashed Boundary Node Component (simple box with dashes)
function DashedBoundaryNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    return (
        <EditableNode data={data} id={id} type="Dashed Boundary" selected={selected} onDelete={handleDelete}>
            <div className="px-4 py-3 bg-gray-50 border-2 border-dashed border-gray-400 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                    <div className="flex gap-0.5">
                        <Minus size={12} className="text-gray-600" />
                        <Minus size={12} className="text-gray-600" />
                        <Minus size={12} className="text-gray-600" />
                        <Minus size={12} className="text-gray-600" />
                        <Minus size={12} className="text-gray-600" />
                    </div>
                    <span className="font-semibold text-gray-900 text-sm">Dashed Boundary</span>
                </div>
            </div>
        </EditableNode>
    );
}

// Boundary/Group Node Component
function BoundaryNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    const [isEditing, setIsEditing] = useState(false);
    const [label, setLabel] = useState(data.label || 'Boundary');
    const [dimensions, setDimensions] = useState({ width: data.width || 400, height: data.height || 300 });
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

    const { setNodes } = useReactFlow();

    const handleResize = (_event: any, { width, height }: { width: number; height: number }) => {
        setDimensions({ width, height });
        setNodes((nds) => 
            nds.map((node) => 
                node.id === id 
                    ? { ...node, width, height, data: { ...node.data, width, height } }
                    : node
            )
        );
        data.width = width;
        data.height = height;
    };

    return (
        <div className="relative group" style={{ width: dimensions.width, height: dimensions.height }}>
            <NodeResizer 
                color="#3b82f6" 
                isVisible={selected}
                minWidth={200}
                minHeight={150}
                onResize={handleResize}
            />
            {selected && (
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        e.preventDefault();
                        handleDelete();
                    }}
                    className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-1 shadow-lg z-10"
                    title="Delete"
                >
                    <X size={12} />
                </button>
            )}
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

// Icon Box Node Component (Legend)
function IconBoxNode({ data, id, selected }: { data: any; id: string; selected?: boolean }) {
    const { deleteElements, setNodes } = useReactFlow();
    const handleDelete = () => {
        deleteElements({ nodes: [{ id }] });
    };
    
    const deviceTypes = data.deviceTypes || [];
    const deviceTypeCounts = data.deviceTypeCounts || {};
    const deviceMap: Record<string, { icon: any; label: string; color: string }> = {
        server: { icon: Server, label: 'Server', color: 'blue' },
        firewall: { icon: Shield, label: 'Firewall', color: 'red' },
        router: { icon: Router, label: 'Router', color: 'green' },
        switch: { icon: Network, label: 'Switch', color: 'purple' },
        cloud: { icon: Cloud, label: 'Cloud', color: 'cyan' },
        database: { icon: Database, label: 'Database', color: 'orange' },
        desktop: { icon: Monitor, label: 'Desktop', color: 'indigo' },
        laptop: { icon: Laptop, label: 'Laptop', color: 'teal' },
        idsidp: { icon: ShieldCheck, label: 'IDS/IDP', color: 'pink' },
        loadbalancer: { icon: Activity, label: 'Load Balancer', color: 'amber' },
        vpngateway: { icon: Lock, label: 'VPN Gateway', color: 'slate' },
        wap: { icon: Radio, label: 'WAP', color: 'emerald' },
        printer: { icon: Printer, label: 'Printer', color: 'rose' },
        personalbox: { icon: User, label: 'Personal Box', color: 'violet' },
    };

    const containerStyle = {
        width: data.width || 250,
        height: data.height || 'auto',
        minWidth: data.width ? undefined : 200,
        minHeight: data.height ? undefined : 100,
    };

    const handleResize = (_event: any, { width, height }: { width: number; height: number }) => {
        setNodes((nds) =>
            nds.map((node) =>
                node.id === id
                    ? { ...node, width, height, data: { ...node.data, width, height } }
                    : node
            )
        );
        data.width = width;
        data.height = height;
    };

    return (
        <div className="relative group" style={containerStyle}>
            <NodeResizer 
                color="#3b82f6" 
                isVisible={selected}
                minWidth={200}
                minHeight={100}
                onResize={handleResize}
            />
            {selected && (
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        e.preventDefault();
                        handleDelete();
                    }}
                    className="absolute -top-2 -right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-1 shadow-lg z-10"
                    title="Delete"
                >
                    <X size={12} />
                </button>
            )}
            <div className="px-4 py-3 bg-white border-2 border-gray-300 rounded-lg shadow-md w-full h-full flex flex-col">
                <div className="font-semibold text-gray-900 text-sm mb-2 border-b pb-1">Legend</div>
                <div className="flex flex-col gap-2 flex-1 overflow-y-auto">
                    {deviceTypes.map((type: string) => {
                        const device = deviceMap[type];
                        if (!device) return null;
                        const Icon = device.icon;
                        const count = deviceTypeCounts[type] || 0;
                        return (
                            <div key={type} className="flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2">
                                    <Icon size={16} className={`text-${device.color}-600`} />
                                    <span className="text-xs text-gray-700">{device.label}</span>
                                </div>
                                <span className="text-xs font-semibold text-gray-500">({count})</span>
                            </div>
                        );
                    })}
                    {deviceTypes.length === 0 && (
                        <span className="text-xs text-gray-500">No devices found</span>
                    )}
                </div>
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
    desktop: DesktopNode,
    idsidp: IdsIdpNode,
    laptop: LaptopNode,
    loadbalancer: LoadBalancerNode,
    vpngateway: VpnGatewayNode,
    wap: WapNode,
    printer: PrinterNode,
    personalbox: PersonalBoxNode,
    textbox: TextBoxNode,
    dashedboundary: DashedBoundaryNode,
    boundary: BoundaryNode,
    iconbox: IconBoxNode,
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
    const networkDiagramContainer = useRef<HTMLDivElement>(null);
    const [reactFlowInstance, setReactFlowInstance] = useState<any>(null);
    const [nodeCounter, setNodeCounter] = useState<Record<string, number>>({});
    const [isFullscreen, setIsFullscreen] = useState(false);
    const [showAlignModal, setShowAlignModal] = useState(false);
    const [selectedNodesForAlign, setSelectedNodesForAlign] = useState<Set<string>>(new Set());
    const [alignDirection, setAlignDirection] = useState<'horizontal' | 'vertical' | null>(null);
    const [showSaveAsModal, setShowSaveAsModal] = useState(false);
    const [showLineStyleModal, setShowLineStyleModal] = useState(false);
    const [pendingConnection, setPendingConnection] = useState<Connection | null>(null);
    const [showHardwareListModal, setShowHardwareListModal] = useState(false);
    const [hardwareList, setHardwareList] = useState<Array<{
        deviceType: string;
        icon: any;
        label: string;
        color: string;
        quantity: number;
        deviceName: string;
        componentType: string;
        manufacturer: string;
        macAddress: string;
        ipAddress: string;
        pointOfContact: string;
        customFields: Record<string, string>;
    }>>([]);
    const [customColumns, setCustomColumns] = useState<Array<{ id: string; name: string }>>([]);
    const [showAddColumnInput, setShowAddColumnInput] = useState(false);
    const [newColumnName, setNewColumnName] = useState('');
    const [editingEdgeLabel, setEditingEdgeLabel] = useState<string | null>(null);
    const [edgeLabelText, setEdgeLabelText] = useState('');
    const edgeLabelInputRef = useRef<HTMLInputElement>(null);

    // Keyboard handler for Delete/Backspace
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if ((e.key === 'Delete' || e.key === 'Backspace') && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
                const selectedIds = nodes.filter(n => n.selected).map(n => n.id);
                if (selectedIds.length === 0) return;
                
                setNodes((nds) => nds.filter(n => !selectedIds.includes(n.id)));
                setEdges((eds) => eds.filter(e => !selectedIds.includes(e.source) && !selectedIds.includes(e.target)));
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [nodes, setNodes, setEdges]);

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
            // Store the pending connection and show modal to choose line style
            setPendingConnection(params);
            setShowLineStyleModal(true);
        },
        []
    );

    const handleLineStyleChoice = (isDashed: boolean) => {
        if (!pendingConnection) return;
        
        const edgeStyle = isDashed 
            ? { strokeWidth: 2, strokeDasharray: '5,5' }
            : { strokeWidth: 2, strokeDasharray: '0' }; // Explicitly set to 0 for solid line
        
        setEdges((eds) => addEdge({ 
            ...pendingConnection, 
            animated: false, // Disable animation - lines should not move
            style: edgeStyle 
        }, eds));
        
        setShowLineStyleModal(false);
        setPendingConnection(null);
    };

    const handleCancelLineStyle = () => {
        setShowLineStyleModal(false);
        setPendingConnection(null);
    };

    const onEdgeDoubleClick = useCallback((event: React.MouseEvent, edge: Edge) => {
        event.stopPropagation();
        setEditingEdgeLabel(edge.id);
        setEdgeLabelText((edge.label as string) || '');
        setTimeout(() => {
            edgeLabelInputRef.current?.focus();
            edgeLabelInputRef.current?.select();
        }, 0);
    }, []);

    const saveEdgeLabel = useCallback((edgeId: string, newLabel: string) => {
        setEdges((eds) =>
            eds.map((edge) =>
                edge.id === edgeId
                    ? { ...edge, label: newLabel || undefined }
                    : edge
            )
        );
        setEditingEdgeLabel(null);
        setEdgeLabelText('');
    }, [setEdges]);

    const cancelEdgeLabelEdit = useCallback(() => {
        setEditingEdgeLabel(null);
        setEdgeLabelText('');
    }, []);

    // Custom edge component with editable label
    const EditableEdge = useCallback(({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, style = {}, markerEnd, label, data }: EdgeProps) => {
        const [edgePath, labelX, labelY] = getBezierPath({
            sourceX,
            sourceY,
            sourcePosition,
            targetX,
            targetY,
            targetPosition,
        });

        const isEditing = editingEdgeLabel === id;
        const currentLabel = isEditing ? edgeLabelText : (label as string || '');

        return (
            <>
                <BaseEdge id={id} path={edgePath} markerEnd={markerEnd} style={style} />
                <EdgeLabelRenderer>
                    <div
                        style={{
                            position: 'absolute',
                            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
                            pointerEvents: 'all',
                            fontSize: '12px',
                            fontWeight: 500,
                        }}
                        className="nodrag nopan"
                    >
                        {isEditing ? (
                            <input
                                ref={edgeLabelInputRef}
                                type="text"
                                value={currentLabel}
                                onChange={(e) => setEdgeLabelText(e.target.value)}
                                onBlur={() => saveEdgeLabel(id, edgeLabelText)}
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                        e.currentTarget.blur();
                                        saveEdgeLabel(id, edgeLabelText);
                                    } else if (e.key === 'Escape') {
                                        cancelEdgeLabelEdit();
                                    }
                                }}
                                className={`px-1.5 py-0.5 text-xs border border-blue-500 outline-none text-center ${
                                    darkMode 
                                        ? 'bg-gray-800 text-white border-blue-400' 
                                        : 'bg-white text-gray-900 border-blue-500'
                                }`}
                                onClick={(e) => e.stopPropagation()}
                                autoFocus
                                style={{ minWidth: '50px', borderRadius: '2px' }}
                            />
                        ) : currentLabel ? (
                            <div
                                className="text-xs text-center font-medium select-none"
                                style={{
                                    color: darkMode ? '#ffffff' : '#1f2937',
                                    textShadow: darkMode 
                                        ? '0 1px 3px rgba(0,0,0,0.9), 0 0 6px rgba(0,0,0,0.7)' 
                                        : '0 1px 2px rgba(255,255,255,1), 0 0 4px rgba(255,255,255,0.8)',
                                    padding: '1px 4px',
                                }}
                                title="Double-click to edit"
                            >
                                {currentLabel}
                            </div>
                        ) : null}
                    </div>
                </EdgeLabelRenderer>
            </>
        );
    }, [editingEdgeLabel, edgeLabelText, darkMode, saveEdgeLabel, cancelEdgeLabelEdit]);

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
                data: { label: 'text' }, // Start with "text" as default label
                width: type === 'textbox' ? 150 : type === 'boundary' ? 400 : undefined,
                height: type === 'textbox' ? 80 : type === 'boundary' ? 300 : undefined,
            };

            setNodes((nds) => nds.concat(newNode));
        },
        [reactFlowInstance, nodeCounter, setNodes]
    );

    const toggleFullscreen = () => {
        if (!networkDiagramContainer.current) return;
        
        if (!isFullscreen) {
            // Enter fullscreen - only the network diagram component
            const element = networkDiagramContainer.current;
            if (element.requestFullscreen) {
                element.requestFullscreen();
            } else if ((element as any).webkitRequestFullscreen) {
                (element as any).webkitRequestFullscreen();
            } else if ((element as any).msRequestFullscreen) {
                (element as any).msRequestFullscreen();
            }
            setIsFullscreen(true);
        } else {
            // Exit fullscreen
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if ((document as any).webkitExitFullscreen) {
                (document as any).webkitExitFullscreen();
            } else if ((document as any).msExitFullscreen) {
                (document as any).msExitFullscreen();
            }
            setIsFullscreen(false);
        }
    };

    // Listen for fullscreen changes
    useEffect(() => {
        const handleFullscreenChange = () => {
            setIsFullscreen(!!document.fullscreenElement);
        };
        document.addEventListener('fullscreenchange', handleFullscreenChange);
        document.addEventListener('webkitfullscreenchange', handleFullscreenChange);
        document.addEventListener('msfullscreenchange', handleFullscreenChange);
        return () => {
            document.removeEventListener('fullscreenchange', handleFullscreenChange);
            document.removeEventListener('webkitfullscreenchange', handleFullscreenChange);
            document.removeEventListener('msfullscreenchange', handleFullscreenChange);
        };
    }, []);

    const startAlign = () => {
        if (nodes.length === 0) {
            alert('Please add nodes to the diagram before aligning.');
            return;
        }
        setSelectedNodesForAlign(new Set());
        setAlignDirection(null);
        setShowAlignModal(true);
    };

    const toggleNodeSelection = (nodeId: string) => {
        setSelectedNodesForAlign(prev => {
            const newSet = new Set(prev);
            if (newSet.has(nodeId)) {
                newSet.delete(nodeId);
            } else {
                newSet.add(nodeId);
            }
            return newSet;
        });
    };

    const executeAlign = () => {
        if (selectedNodesForAlign.size < 2) {
            alert('Please select at least 2 nodes to align.');
            return;
        }
        if (!alignDirection) {
            alert('Please select alignment direction (horizontal or vertical).');
            return;
        }

        const selectedNodes = nodes.filter(n => selectedNodesForAlign.has(n.id));
        
        if (alignDirection === 'horizontal') {
            // Align horizontally (same Y position) - use the first selected node's Y as reference
            const referenceY = selectedNodes[0].position.y;
            const updatedNodes = nodes.map(node => {
                if (selectedNodesForAlign.has(node.id)) {
                    return { ...node, position: { ...node.position, y: referenceY } };
                }
                return node;
            });
            setNodes(updatedNodes);
        } else {
            // Align vertically (same X position) - use the first selected node's X as reference
            const referenceX = selectedNodes[0].position.x;
            const updatedNodes = nodes.map(node => {
                if (selectedNodesForAlign.has(node.id)) {
                    return { ...node, position: { ...node.position, x: referenceX } };
                }
                return node;
            });
            setNodes(updatedNodes);
        }

        setShowAlignModal(false);
        setSelectedNodesForAlign(new Set());
        setAlignDirection(null);
    };

    const handleSaveAs = (format: 'local' | 'png' | 'visio') => {
        setShowSaveAsModal(false);
        if (format === 'local') {
            setShowSaveModal(true);
        } else if (format === 'png') {
            exportToPNG();
        } else if (format === 'visio') {
            exportToVisio();
        }
    };

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

    const exportToVisio = async () => {
        if (!reactFlowInstance || nodes.length === 0) {
            alert('Please add some nodes to the diagram before exporting.');
            return;
        }

        try {
            // Create Visio .vsdx file structure (it's a ZIP with XML files)
            const zip = new JSZip();

            // Create [Content_Types].xml
            const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>
    <Override PartName="/visio/pages/_rels/pages.xml.rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>
    <Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.main+xml"/>
    <Override PartName="/visio/_rels/document.xml.rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Override PartName="/visio/windows.xml" ContentType="application/vnd.ms-visio.windows+xml"/>
    <Override PartName="/visio/pages/_rels/pages.xml.rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
</Types>`;
            zip.file('[Content_Types].xml', contentTypes);

            // Create _rels/.rels
            const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml"/>
    <Relationship Id="rId2" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="visio/pages/pages.xml"/>
</Relationships>`;
            zip.folder('_rels')!.file('.rels', rels);

            // Create visio/document.xml
            const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xml:space="preserve">
    <DocumentSettings/>
    <Colors/>
    <FaceNames/>
    <StyleSheets/>
    <DocumentSheet/>
    <Pages/>
    <Windows/>
</VisioDocument>`;
            zip.folder('visio')!.file('document.xml', documentXml);

            // Create visio/_rels/document.xml.rels
            const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml"/>
    <Relationship Id="rId2" Type="http://schemas.microsoft.com/visio/2010/relationships/windows" Target="windows.xml"/>
</Relationships>`;
            zip.folder('visio')!.folder('_rels')!.file('document.xml.rels', docRels);

            // Create visio/windows.xml
            const windows = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Windows xmlns="http://schemas.microsoft.com/office/visio/2012/main">
    <Window ID="0" WindowType="Drawing" WindowState="1073741824"/>
</Windows>`;
            zip.folder('visio')!.file('windows.xml', windows);

            // Create visio/pages/pages.xml with actual diagram content
            const pageId = '1';
            let shapesXml = '';
            let connectorsXml = '';

            // Convert nodes to Visio shapes
            nodes.forEach((node, index) => {
                const x = node.position.x;
                const y = node.position.y;
                const width = 100;
                const height = 60;
                
                // Map node types to Visio shapes
                let shapeType = 'Rectangle';
                if (node.type === 'server') shapeType = 'Server';
                else if (node.type === 'firewall') shapeType = 'Firewall';
                else if (node.type === 'router') shapeType = 'Router';
                else if (node.type === 'switch') shapeType = 'Switch';
                else if (node.type === 'cloud') shapeType = 'Cloud';
                else if (node.type === 'database') shapeType = 'Database';
                else if (node.type === 'desktop') shapeType = 'Desktop';
                else if (node.type === 'idsidp') shapeType = 'IDS/IDP';
                else if (node.type === 'laptop') shapeType = 'Laptop';
                else if (node.type === 'loadbalancer') shapeType = 'Load Balancer';
                else if (node.type === 'vpngateway') shapeType = 'VPN Gateway';
                else if (node.type === 'wap') shapeType = 'WAP';
                else if (node.type === 'printer') shapeType = 'Printer';
                else if (node.type === 'personalbox') shapeType = 'Personal Box';
                else if (node.type === 'dashedboundary') shapeType = 'Dashed Boundary';
                
                const label = node.data?.label || `${node.type} ${index + 1}`;
                
                shapesXml += `
    <Shape ID="${index + 2}" Type="Shape" Master="0">
        <Cell N="PinX" V="${x}"/>
        <Cell N="PinY" V="${y}"/>
        <Cell N="Width" V="${width}"/>
        <Cell N="Height" V="${height}"/>
        <Cell N="LocPinX" V="${width / 2}"/>
        <Cell N="LocPinY" V="${height / 2}"/>
        <Text>${label}</Text>
    </Shape>`;
            });

            // Convert edges to Visio connectors
            edges.forEach((edge, index) => {
                const sourceNode = nodes.find(n => n.id === edge.source);
                const targetNode = nodes.find(n => n.id === edge.target);
                if (!sourceNode || !targetNode) return;

                const x1 = sourceNode.position.x;
                const y1 = sourceNode.position.y;
                const x2 = targetNode.position.x;
                const y2 = targetNode.position.y;

                connectorsXml += `
    <Shape ID="${nodes.length + index + 2}" Type="Shape" Master="1">
        <Cell N="BeginX" V="${x1}"/>
        <Cell N="BeginY" V="${y1}"/>
        <Cell N="EndX" V="${x2}"/>
        <Cell N="EndY" V="${y2}"/>
    </Shape>`;
            });

            const pages = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
    <Page ID="${pageId}" NameU="${diagramName}" IsCustomNameU="1">
        <PageSheet>
            <Cell N="PageWidth" V="11"/>
            <Cell N="PageHeight" V="8.5"/>
        </PageSheet>
        <Shapes>${shapesXml}${connectorsXml}
        </Shapes>
    </Page>
</Pages>`;
            zip.folder('visio')!.folder('pages')!.file('pages.xml', pages);

            // Create visio/pages/_rels/pages.xml.rels
            const pagesRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`;
            zip.folder('visio')!.folder('pages')!.folder('_rels')!.file('pages.xml.rels', pagesRels);

            // Generate and download the .vsdx file
            const blob = await zip.generateAsync({ type: 'blob' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `${diagramName.replace(/[^a-zA-Z0-9]/g, '_')}.vsdx`;
            link.click();
            URL.revokeObjectURL(url);

            alert(`Successfully exported to Visio format!`);
        } catch (error: any) {
            console.error('Visio export error:', error);
            alert(`Error exporting to Visio: ${error.message}`);
        }
    };

    // Template definitions
    const templates = {
        'cloud': {
            name: 'Cloud Environment',
            description: 'AWS/Azure/GCP cloud infrastructure with load balancers, VPCs, and services',
            nodes: [
                { id: 'cloud-1', type: 'cloud', position: { x: 400, y: 80 }, data: { label: 'Public Cloud' } },
                { id: 'lb-1', type: 'loadbalancer', position: { x: 400, y: 200 }, data: { label: 'Load Balancer' } },
                { id: 'fw-1', type: 'firewall', position: { x: 400, y: 320 }, data: { label: 'WAF' } },
                { id: 'app-1', type: 'server', position: { x: 250, y: 450 }, data: { label: 'App Server 1' } },
                { id: 'app-2', type: 'server', position: { x: 550, y: 450 }, data: { label: 'App Server 2' } },
                { id: 'db-1', type: 'database', position: { x: 400, y: 580 }, data: { label: 'Database' } },
                { id: 'vpn-1', type: 'vpngateway', position: { x: 650, y: 320 }, data: { label: 'VPN Gateway' } },
            ],
            edges: [
                { id: 'e1', source: 'cloud-1', target: 'lb-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e2', source: 'lb-1', target: 'fw-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e3', source: 'fw-1', target: 'app-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e4', source: 'fw-1', target: 'app-2', animated: false, style: { strokeWidth: 2 } },
                { id: 'e5', source: 'app-1', target: 'db-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e6', source: 'app-2', target: 'db-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e7', source: 'fw-1', target: 'vpn-1', animated: false, style: { strokeWidth: 2 } },
            ],
        },
        'small-business': {
            name: 'Small Business',
            description: 'Basic office network with router, firewall, switch, and workstations',
            nodes: [
                { id: 'router-1', type: 'router', position: { x: 400, y: 80 }, data: { label: 'Router' } },
                { id: 'fw-1', type: 'firewall', position: { x: 400, y: 200 }, data: { label: 'Firewall' } },
                { id: 'switch-1', type: 'switch', position: { x: 400, y: 320 }, data: { label: 'Switch' } },
                { id: 'server-1', type: 'server', position: { x: 250, y: 450 }, data: { label: 'File Server' } },
                { id: 'desktop-1', type: 'desktop', position: { x: 400, y: 450 }, data: { label: 'Desktop 1' } },
                { id: 'desktop-2', type: 'desktop', position: { x: 550, y: 450 }, data: { label: 'Desktop 2' } },
                { id: 'printer-1', type: 'printer', position: { x: 250, y: 580 }, data: { label: 'Printer' } },
                { id: 'wap-1', type: 'wap', position: { x: 550, y: 580 }, data: { label: 'Wi-Fi Access' } },
            ],
            edges: [
                { id: 'e1', source: 'router-1', target: 'fw-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e2', source: 'fw-1', target: 'switch-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e3', source: 'switch-1', target: 'server-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e4', source: 'switch-1', target: 'desktop-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e5', source: 'switch-1', target: 'desktop-2', animated: false, style: { strokeWidth: 2 } },
                { id: 'e6', source: 'switch-1', target: 'printer-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e7', source: 'switch-1', target: 'wap-1', animated: false, style: { strokeWidth: 2 } },
            ],
        },
        'dod': {
            name: 'DoD/Government',
            description: 'Defense network with DMZ, enclaves, IDS/IPS, and strict segmentation',
            nodes: [
                { id: 'internet', type: 'cloud', position: { x: 500, y: 50 }, data: { label: 'Internet' } },
                { id: 'fw-perimeter', type: 'firewall', position: { x: 500, y: 180 }, data: { label: 'Perimeter FW' } },
                { id: 'dmz-boundary', type: 'boundary', position: { x: 350, y: 300 }, data: { label: 'DMZ Enclave' }, width: 600, height: 200 },
                { id: 'ids-dmz', type: 'idsidp', position: { x: 450, y: 400 }, data: { label: 'IDS/IPS' } },
                { id: 'web-dmz', type: 'server', position: { x: 600, y: 400 }, data: { label: 'Web Server' } },
                { id: 'fw-internal', type: 'firewall', position: { x: 500, y: 560 }, data: { label: 'Internal FW' } },
                { id: 'internal-boundary', type: 'boundary', position: { x: 350, y: 680 }, data: { label: 'Internal Enclave' }, width: 600, height: 200 },
                { id: 'server-internal', type: 'server', position: { x: 450, y: 780 }, data: { label: 'Internal Server' } },
                { id: 'db-internal', type: 'database', position: { x: 600, y: 780 }, data: { label: 'Database' } },
                { id: 'desktop-internal', type: 'desktop', position: { x: 750, y: 780 }, data: { label: 'Workstation' } },
                { id: 'ids-internal', type: 'idsidp', position: { x: 500, y: 940 }, data: { label: 'IDS/IPS' } },
            ],
            edges: [
                { id: 'e1', source: 'internet', target: 'fw-perimeter', animated: false, style: { strokeWidth: 2 } },
                { id: 'e2', source: 'fw-perimeter', target: 'ids-dmz', animated: false, style: { strokeWidth: 2 } },
                { id: 'e3', source: 'fw-perimeter', target: 'web-dmz', animated: false, style: { strokeWidth: 2 } },
                { id: 'e4', source: 'web-dmz', target: 'fw-internal', animated: false, style: { strokeWidth: 2, strokeDasharray: '5,5' } },
                { id: 'e5', source: 'fw-internal', target: 'server-internal', animated: false, style: { strokeWidth: 2 } },
                { id: 'e6', source: 'fw-internal', target: 'db-internal', animated: false, style: { strokeWidth: 2 } },
                { id: 'e7', source: 'fw-internal', target: 'desktop-internal', animated: false, style: { strokeWidth: 2 } },
                { id: 'e8', source: 'ids-internal', target: 'db-internal', animated: false, style: { strokeWidth: 2 } },
            ],
        },
        'enterprise': {
            name: 'Enterprise',
            description: 'Large-scale enterprise network with multi-tier architecture and redundancy',
            nodes: [
                { id: 'internet', type: 'cloud', position: { x: 500, y: 80 }, data: { label: 'Internet' } },
                { id: 'router-edge-1', type: 'router', position: { x: 350, y: 200 }, data: { label: 'Edge Router 1' } },
                { id: 'router-edge-2', type: 'router', position: { x: 650, y: 200 }, data: { label: 'Edge Router 2' } },
                { id: 'fw-1', type: 'firewall', position: { x: 350, y: 320 }, data: { label: 'FW 1' } },
                { id: 'fw-2', type: 'firewall', position: { x: 650, y: 320 }, data: { label: 'FW 2' } },
                { id: 'lb-1', type: 'loadbalancer', position: { x: 500, y: 440 }, data: { label: 'Load Balancer' } },
                { id: 'switch-core', type: 'switch', position: { x: 500, y: 560 }, data: { label: 'Core Switch' } },
                { id: 'server-web-1', type: 'server', position: { x: 300, y: 680 }, data: { label: 'Web 1' } },
                { id: 'server-web-2', type: 'server', position: { x: 500, y: 680 }, data: { label: 'Web 2' } },
                { id: 'server-app-1', type: 'server', position: { x: 700, y: 680 }, data: { label: 'App 1' } },
                { id: 'db-1', type: 'database', position: { x: 350, y: 800 }, data: { label: 'DB Cluster' } },
                { id: 'db-2', type: 'database', position: { x: 650, y: 800 }, data: { label: 'DB Replica' } },
            ],
            edges: [
                { id: 'e1', source: 'internet', target: 'router-edge-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e2', source: 'internet', target: 'router-edge-2', animated: false, style: { strokeWidth: 2 } },
                { id: 'e3', source: 'router-edge-1', target: 'fw-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e4', source: 'router-edge-2', target: 'fw-2', animated: false, style: { strokeWidth: 2 } },
                { id: 'e5', source: 'fw-1', target: 'lb-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e6', source: 'fw-2', target: 'lb-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e7', source: 'lb-1', target: 'switch-core', animated: false, style: { strokeWidth: 2 } },
                { id: 'e8', source: 'switch-core', target: 'server-web-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e9', source: 'switch-core', target: 'server-web-2', animated: false, style: { strokeWidth: 2 } },
                { id: 'e10', source: 'switch-core', target: 'server-app-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e11', source: 'server-web-1', target: 'db-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e12', source: 'server-web-2', target: 'db-1', animated: false, style: { strokeWidth: 2 } },
                { id: 'e13', source: 'db-1', target: 'db-2', animated: false, style: { strokeWidth: 2, strokeDasharray: '5,5' } },
            ],
        },
        'remote-work': {
            name: 'Remote Work',
            description: 'Hybrid work environment with VPN, office network, and remote connections',
            nodes: [
                { id: 'internet', type: 'cloud', position: { x: 500, y: 80 }, data: { label: 'Internet' } },
                { id: 'vpn-gateway', type: 'vpngateway', position: { x: 500, y: 200 }, data: { label: 'VPN Gateway' } },
                { id: 'fw-office', type: 'firewall', position: { x: 500, y: 320 }, data: { label: 'Office Firewall' } },
                { id: 'router-office', type: 'router', position: { x: 500, y: 440 }, data: { label: 'Office Router' } },
                { id: 'switch-office', type: 'switch', position: { x: 500, y: 560 }, data: { label: 'Office Switch' } },
                { id: 'server-office', type: 'server', position: { x: 350, y: 680 }, data: { label: 'Office Server' } },
                { id: 'desktop-office', type: 'desktop', position: { x: 500, y: 680 }, data: { label: 'Office PC' } },
                { id: 'wap-office', type: 'wap', position: { x: 650, y: 680 }, data: { label: 'Office Wi-Fi' } },
                { id: 'laptop-remote-1', type: 'laptop', position: { x: 200, y: 200 }, data: { label: 'Remote Worker 1' } },
                { id: 'laptop-remote-2', type: 'laptop', position: { x: 800, y: 200 }, data: { label: 'Remote Worker 2' } },
            ],
            edges: [
                { id: 'e1', source: 'internet', target: 'vpn-gateway', animated: false, style: { strokeWidth: 2 } },
                { id: 'e2', source: 'vpn-gateway', target: 'fw-office', animated: false, style: { strokeWidth: 2 } },
                { id: 'e3', source: 'fw-office', target: 'router-office', animated: false, style: { strokeWidth: 2 } },
                { id: 'e4', source: 'router-office', target: 'switch-office', animated: false, style: { strokeWidth: 2 } },
                { id: 'e5', source: 'switch-office', target: 'server-office', animated: false, style: { strokeWidth: 2 } },
                { id: 'e6', source: 'switch-office', target: 'desktop-office', animated: false, style: { strokeWidth: 2 } },
                { id: 'e7', source: 'switch-office', target: 'wap-office', animated: false, style: { strokeWidth: 2 } },
                { id: 'e8', source: 'internet', target: 'laptop-remote-1', animated: false, style: { strokeWidth: 2, strokeDasharray: '5,5' } },
                { id: 'e9', source: 'internet', target: 'laptop-remote-2', animated: false, style: { strokeWidth: 2, strokeDasharray: '5,5' } },
                { id: 'e10', source: 'laptop-remote-1', target: 'vpn-gateway', animated: false, style: { strokeWidth: 2, strokeDasharray: '5,5' } },
                { id: 'e11', source: 'laptop-remote-2', target: 'vpn-gateway', animated: false, style: { strokeWidth: 2, strokeDasharray: '5,5' } },
            ],
        },
    };

    const loadTemplate = (templateKey: keyof typeof templates) => {
        const template = templates[templateKey];
        if (!template) return;
        
        if (nodes.length > 0 || edges.length > 0) {
            if (!window.confirm('This will replace your current diagram. Continue?')) {
                return;
            }
        }
        
        // Generate unique IDs for nodes and edges to avoid conflicts
        const nodeIdMap: Record<string, string> = {};
        const newNodes = template.nodes.map(node => {
            const newId = `${node.id}-${Date.now()}`;
            nodeIdMap[node.id] = newId;
            return {
                ...node,
                id: newId,
            };
        });
        
        const newEdges = template.edges.map(edge => {
            const newSource = nodeIdMap[edge.source] || edge.source;
            const newTarget = nodeIdMap[edge.target] || edge.target;
            return {
                ...edge,
                id: `${edge.id}-${Date.now()}`,
                source: newSource,
                target: newTarget,
            };
        });
        
        setNodes(newNodes);
        setEdges(newEdges);
        setDiagramName(template.name);
        setSelectedDiagram(null);
    };

    const createIconBox = () => {
        // Find all device types and count them (excluding textbox, boundary, dashedboundary, iconbox)
        const deviceTypeCounts: Record<string, number> = {};
        nodes.forEach(node => {
            if (node.type && 
                node.type !== 'textbox' && 
                node.type !== 'boundary' && 
                node.type !== 'dashedboundary' &&
                node.type !== 'iconbox') {
                deviceTypeCounts[node.type] = (deviceTypeCounts[node.type] || 0) + 1;
            }
        });

        const deviceTypes = Object.keys(deviceTypeCounts);

        if (deviceTypes.length === 0) {
            alert('No devices found in the diagram. Add some devices first.');
            return;
        }

        // Remove any existing icon box
        const existingIconBox = nodes.find(n => n.type === 'iconbox');
        if (existingIconBox) {
            setNodes((nds) => nds.filter(n => n.id !== existingIconBox.id));
        }

        // Calculate bottom-right position
        let maxX = 0;
        let maxY = 0;
        nodes.forEach(node => {
            if (node.type !== 'iconbox') {
                const nodeRight = node.position.x + (node.width || 150);
                const nodeBottom = node.position.y + (node.height || 100);
                maxX = Math.max(maxX, nodeRight);
                maxY = Math.max(maxY, nodeBottom);
            }
        });

        // Position icon box at bottom right with some padding
        const iconBoxWidth = 250;
        const iconBoxHeight = 100 + (deviceTypes.length * 24); // Base height + height per item
        const padding = 50;
        const iconBoxX = maxX + padding;
        const iconBoxY = maxY + padding;

        const iconBoxNode: Node = {
            id: `iconbox-${Date.now()}`,
            type: 'iconbox',
            position: { x: iconBoxX, y: iconBoxY },
            data: { 
                label: 'Legend',
                deviceTypes: deviceTypes,
                deviceTypeCounts: deviceTypeCounts,
                width: iconBoxWidth,
                height: iconBoxHeight,
            },
            width: iconBoxWidth,
            height: iconBoxHeight,
        };

        setNodes((nds) => nds.concat(iconBoxNode));
    };

    const createHardwareList = () => {
        // Device type mapping with icons and labels
        const deviceMap: Record<string, { icon: any; label: string; color: string }> = {
            server: { icon: Server, label: 'Server', color: 'blue' },
            firewall: { icon: Shield, label: 'Firewall', color: 'red' },
            router: { icon: Router, label: 'Router', color: 'green' },
            switch: { icon: Network, label: 'Switch', color: 'purple' },
            cloud: { icon: Cloud, label: 'Cloud', color: 'cyan' },
            database: { icon: Database, label: 'Database', color: 'orange' },
            desktop: { icon: Monitor, label: 'Desktop', color: 'indigo' },
            laptop: { icon: Laptop, label: 'Laptop', color: 'teal' },
            idsidp: { icon: ShieldCheck, label: 'IDS/IDP', color: 'pink' },
            loadbalancer: { icon: Activity, label: 'Load Balancer', color: 'amber' },
            vpngateway: { icon: Lock, label: 'VPN Gateway', color: 'slate' },
            wap: { icon: Radio, label: 'WAP', color: 'emerald' },
            printer: { icon: Printer, label: 'Printer', color: 'rose' },
            personalbox: { icon: User, label: 'Personal Box', color: 'violet' },
        };

        // Count devices by type (excluding non-hardware nodes)
        const deviceCounts: Record<string, number> = {};
        nodes.forEach(node => {
            if (node.type && 
                node.type !== 'textbox' && 
                node.type !== 'boundary' && 
                node.type !== 'dashedboundary' &&
                node.type !== 'iconbox' &&
                deviceMap[node.type]) {
                deviceCounts[node.type] = (deviceCounts[node.type] || 0) + 1;
            }
        });

        // Generate hardware list
        const hardwareListData = Object.entries(deviceCounts).map(([deviceType, quantity]) => {
            const device = deviceMap[deviceType];
            return {
                deviceType,
                icon: device.icon,
                label: device.label,
                color: device.color,
                quantity,
                deviceName: '',
                componentType: '',
                manufacturer: '',
                macAddress: '',
                ipAddress: '',
                pointOfContact: '',
                customFields: {} as Record<string, string>,
            };
        });

        if (hardwareListData.length === 0) {
            alert('No hardware devices found in the diagram. Add some devices first.');
            return;
        }

        setHardwareList(hardwareListData);
        setCustomColumns([]); // Reset custom columns when creating new list
        setShowHardwareListModal(true);
    };

    const updateHardwareListField = (deviceType: string, field: string, value: string) => {
        setHardwareList(prev => prev.map(item => 
            item.deviceType === deviceType 
                ? { ...item, [field]: value }
                : item
        ));
    };

    const updateHardwareListCustomField = (deviceType: string, columnId: string, value: string) => {
        setHardwareList(prev => prev.map(item => 
            item.deviceType === deviceType 
                ? { 
                    ...item, 
                    customFields: { 
                        ...item.customFields, 
                        [columnId]: value 
                    } 
                }
                : item
        ));
    };

    const addCustomColumn = () => {
        if (newColumnName && newColumnName.trim()) {
            const newColumn = { 
                id: `custom-${Date.now()}`, 
                name: newColumnName.trim() 
            };
            setCustomColumns(prev => [...prev, newColumn]);
            // Initialize custom field for all hardware items
            setHardwareList(prev => prev.map(item => ({
                ...item,
                customFields: {
                    ...item.customFields,
                    [newColumn.id]: ''
                }
            })));
            setNewColumnName('');
            setShowAddColumnInput(false);
        }
    };

    const handleAddColumnKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter') {
            addCustomColumn();
        } else if (e.key === 'Escape') {
            setShowAddColumnInput(false);
            setNewColumnName('');
        }
    };

    const removeCustomColumn = (columnId: string) => {
        setCustomColumns(prev => prev.filter(col => col.id !== columnId));
        setHardwareList(prev => prev.map(item => {
            const newCustomFields = { ...item.customFields };
            delete newCustomFields[columnId];
            return { ...item, customFields: newCustomFields };
        }));
    };

    const exportHardwareListToCSV = () => {
        const headers = [
            'Device Type', 
            'Quantity', 
            'Device Name', 
            'Component Type', 
            'Manufacturer', 
            'MAC Address', 
            'IP Address', 
            'Point of Contact',
            ...customColumns.map(col => col.name)
        ];
        const rows = hardwareList.map(item => [
            item.label,
            item.quantity.toString(),
            item.deviceName || '',
            item.componentType || '',
            item.manufacturer || '',
            item.macAddress || '',
            item.ipAddress || '',
            item.pointOfContact || '',
            ...customColumns.map(col => item.customFields[col.id] || '')
        ]);

        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell.replace(/"/g, '""')}"`).join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', `hardware_list_${diagramName.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    };

    const copyHardwareList = () => {
        const headers = [
            'Device Type', 
            'Quantity', 
            'Device Name', 
            'Component Type', 
            'Manufacturer', 
            'MAC Address', 
            'IP Address', 
            'Point of Contact',
            ...customColumns.map(col => col.name)
        ];
        const rows = hardwareList.map(item => [
            item.label,
            item.quantity.toString(),
            item.deviceName || '',
            item.componentType || '',
            item.manufacturer || '',
            item.macAddress || '',
            item.ipAddress || '',
            item.pointOfContact || '',
            ...customColumns.map(col => item.customFields[col.id] || '')
        ]);

        const textContent = [
            headers.join('\t'),
            ...rows.map(row => row.join('\t'))
        ].join('\n');

        navigator.clipboard.writeText(textContent).then(() => {
            alert('Hardware list copied to clipboard!');
        }).catch(err => {
            console.error('Failed to copy:', err);
            alert('Failed to copy hardware list to clipboard.');
        });
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
        <div ref={networkDiagramContainer} className="flex h-full">
            {/* Left Sidebar - Device Palette (wider for grid) - Always visible */}
            <div className={`w-32 border-r ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-gray-50 border-gray-200'} p-2 overflow-y-auto`}>
                <h3 className={`font-semibold mb-2 text-xs ${darkMode ? 'text-white' : 'text-gray-900'}`}>Devices</h3>

                <div className="grid grid-cols-2 gap-1.5 mb-4">
                    {[
                        { type: 'server', icon: Server, label: 'Server', color: 'blue' },
                        { type: 'firewall', icon: Shield, label: 'Firewall', color: 'red' },
                        { type: 'router', icon: Router, label: 'Router', color: 'green' },
                        { type: 'switch', icon: Network, label: 'Switch', color: 'purple' },
                        { type: 'cloud', icon: Cloud, label: 'Cloud', color: 'cyan' },
                        { type: 'database', icon: Database, label: 'Database', color: 'orange' },
                        { type: 'desktop', icon: Monitor, label: 'Desktop', color: 'indigo' },
                        { type: 'laptop', icon: Laptop, label: 'Laptop', color: 'teal' },
                        { type: 'idsidp', icon: ShieldCheck, label: 'IDS/IDP', color: 'pink' },
                        { type: 'loadbalancer', icon: Activity, label: 'Load Bal', color: 'amber' },
                        { type: 'vpngateway', icon: Lock, label: 'VPN', color: 'slate' },
                        { type: 'wap', icon: Radio, label: 'WAP', color: 'emerald' },
                        { type: 'printer', icon: Printer, label: 'Printer', color: 'rose' },
                        { type: 'personalbox', icon: User, label: 'Personal', color: 'violet' },
                        { type: 'textbox', icon: Type, label: 'Text', color: 'gray' },
                        { type: 'linetext', icon: Minus, label: 'Line Text', color: 'gray' },
                        { type: 'dashedboundary', icon: Minus, label: 'Dashed', color: 'gray' },
                        { type: 'boundary', icon: Square, label: 'Boundary', color: 'gray' },
                    ].map((device) => {
                        const Icon = device.icon;
                        return (
                            <div
                                key={device.type}
                                draggable
                                onDragStart={(e) => e.dataTransfer.setData('application/reactflow', device.type)}
                                className={`p-1.5 border-2 border-dashed rounded cursor-move transition-all hover:shadow-md text-xs ${
                                    darkMode 
                                        ? 'border-gray-600 bg-gray-700 hover:border-gray-500' 
                                        : 'border-gray-300 bg-white hover:border-gray-400'
                                }`}
                                title={device.label}
                            >
                                <div className="flex flex-col items-center gap-0.5">
                                    <Icon size={14} className={`text-${device.color}-600`} />
                                    <span className={`text-[8px] font-medium leading-tight text-center ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                                        {device.label}
                                    </span>
                                </div>
                            </div>
                        );
                    })}
                </div>

                <div className="pt-3 border-t border-gray-300">
                    <h4 className={`font-semibold mb-1.5 text-xs ${darkMode ? 'text-white' : 'text-gray-900'}`}>Templates</h4>
                    <div className="space-y-1 mb-3 max-h-48 overflow-y-auto">
                        {Object.entries(templates).map(([key, template]) => (
                            <div
                                key={key}
                                className={`p-1.5 rounded border cursor-pointer transition-all text-xs ${
                                    darkMode 
                                        ? 'bg-gray-700 border-gray-600 hover:bg-gray-600 hover:border-gray-500' 
                                        : 'bg-white border-gray-200 hover:bg-gray-50 hover:border-gray-300'
                                }`}
                                onClick={() => loadTemplate(key as keyof typeof templates)}
                                title={template.description}
                            >
                                <div className={`font-medium text-[10px] ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                    {template.name}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="pt-3 border-t border-gray-300">
                    <h4 className={`font-semibold mb-1.5 text-xs ${darkMode ? 'text-white' : 'text-gray-900'}`}>Saved</h4>
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                        {savedDiagrams.map((diagram) => (
                            <div
                                key={diagram.id}
                                className={`p-1.5 rounded border cursor-pointer transition-all text-xs ${
                                    selectedDiagram === diagram.id
                                        ? darkMode ? 'bg-blue-900 border-blue-600' : 'bg-blue-50 border-blue-300'
                                        : darkMode ? 'bg-gray-700 border-gray-600 hover:bg-gray-600' : 'bg-white border-gray-200 hover:bg-gray-50'
                                }`}
                                onClick={() => loadDiagram(diagram.id)}
                                title={diagram.name}
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex-1 min-w-0">
                                        <div className={`font-medium truncate text-[10px] ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                            {diagram.name}
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
                            <p className={`text-[10px] text-center py-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                No saved
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
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setShowSaveAsModal(true)}
                            className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                        >
                            <Save size={14} /> Save As
                        </button>
                        <button
                            onClick={startAlign}
                            className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                            title="Align selected nodes"
                        >
                            <AlignLeft size={14} /> Align
                        </button>
                        <button
                            onClick={createIconBox}
                            className="px-3 py-1 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                            title="Create legend box with all device types"
                        >
                            <List size={14} /> Icon
                        </button>
                        <button
                            onClick={createHardwareList}
                            className="px-3 py-1 bg-teal-600 hover:bg-teal-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                            title="Generate hardware list from diagram"
                        >
                            <HardDrive size={14} /> Hardware List
                        </button>
                        <button
                            onClick={clearDiagram}
                            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                        >
                            <Trash2 size={14} /> Clear
                        </button>
                        <button
                            onClick={toggleFullscreen}
                            className="px-3 py-1 bg-gray-600 hover:bg-gray-700 text-white text-sm font-medium rounded-lg flex items-center gap-1"
                            title={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
                        >
                            {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
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
                        onEdgeDoubleClick={onEdgeDoubleClick}
                        onInit={setReactFlowInstance}
                        onDrop={onDrop}
                        onDragOver={onDragOver}
                        nodeTypes={nodeTypes}
                        edgeTypes={{
                            default: EditableEdge,
                            smoothstep: EditableEdge,
                            straight: EditableEdge,
                        }}
                        fitView
                        connectionLineStyle={{ strokeWidth: 2 }}
                        defaultEdgeOptions={{ 
                            animated: false, // Disable animation by default
                            style: { strokeWidth: 2 },
                            type: 'smoothstep',
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
                                if (node.type === 'desktop') return '#6366f1';
                                if (node.type === 'idsidp') return '#ec4899';
                                if (node.type === 'laptop') return '#14b8a6';
                                if (node.type === 'loadbalancer') return '#f59e0b';
                                if (node.type === 'vpngateway') return '#64748b';
                                if (node.type === 'wap') return '#10b981';
                                if (node.type === 'printer') return '#f43f5e';
                                if (node.type === 'personalbox') return '#8b5cf6';
                                if (node.type === 'textbox') return '#9ca3af';
                                if (node.type === 'linetext') return '#4b5563';
                                if (node.type === 'dashedboundary') return '#6b7280';
                                if (node.type === 'boundary') return '#6b7280';
                                if (node.type === 'iconbox') return '#ffffff';
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
                    <div className={`rounded-xl shadow-2xl max-w-md w-full mx-4 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                        <div className={`px-6 py-4 border-b flex items-center justify-between ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-100'}`}>
                            <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Save Diagram</h3>
                            <button onClick={() => setShowSaveModal(false)} className={`${darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-600'}`}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>Diagram Name</label>
                                <input
                                    type="text"
                                    value={diagramName}
                                    onChange={(e) => setDiagramName(e.target.value)}
                                    className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                        darkMode 
                                            ? 'bg-gray-700 border-gray-600 text-white' 
                                            : 'border-gray-300'
                                    }`}
                                    placeholder="Enter diagram name"
                                />
                            </div>
                            <div className="flex justify-end gap-3">
                                <button
                                    onClick={() => setShowSaveModal(false)}
                                    className={`px-4 py-2 text-sm font-medium ${darkMode ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}
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

            {/* Save As Modal */}
            {showSaveAsModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className={`rounded-xl shadow-2xl max-w-md w-full mx-4 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                        <div className={`px-6 py-4 border-b flex items-center justify-between ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-100'}`}>
                            <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Save As</h3>
                            <button onClick={() => setShowSaveAsModal(false)} className={`${darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-600'}`}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className={`block text-sm font-medium mb-3 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                                    Choose file format:
                                </label>
                                <div className="space-y-2">
                                    <button
                                        onClick={() => handleSaveAs('local')}
                                        className={`w-full px-4 py-3 rounded-lg border-2 transition-all text-left ${
                                            darkMode
                                                ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                        }`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <Save size={20} className="text-blue-600" />
                                            <div>
                                                <div className="font-medium">Save to Browser</div>
                                                <div className="text-xs opacity-75">Save diagram to browser storage</div>
                                            </div>
                                        </div>
                                    </button>
                                    <button
                                        onClick={() => handleSaveAs('png')}
                                        className={`w-full px-4 py-3 rounded-lg border-2 transition-all text-left ${
                                            darkMode
                                                ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                        }`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <Download size={20} className="text-green-600" />
                                            <div>
                                                <div className="font-medium">Export as PNG</div>
                                                <div className="text-xs opacity-75">Download as PNG image file</div>
                                            </div>
                                        </div>
                                    </button>
                                    <button
                                        onClick={() => handleSaveAs('visio')}
                                        className={`w-full px-4 py-3 rounded-lg border-2 transition-all text-left ${
                                            darkMode
                                                ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                        }`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <FileText size={20} className="text-indigo-600" />
                                            <div>
                                                <div className="font-medium">Export as Visio</div>
                                                <div className="text-xs opacity-75">Download as .vsdx file (Microsoft Visio)</div>
                                            </div>
                                        </div>
                                    </button>
                                </div>
                            </div>
                            <div className="flex justify-end">
                                <button
                                    onClick={() => setShowSaveAsModal(false)}
                                    className={`px-4 py-2 text-sm font-medium ${darkMode ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Alignment Modal */}
            {showAlignModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className={`rounded-xl shadow-2xl max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                        <div className={`px-6 py-4 border-b flex items-center justify-between ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-100'}`}>
                            <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Align Nodes</h3>
                            <button onClick={() => {
                                setShowAlignModal(false);
                                setSelectedNodesForAlign(new Set());
                                setAlignDirection(null);
                            }} className={`${darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-600'}`}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className={`block text-sm font-medium mb-3 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                                    Select nodes to align (at least 2):
                                </label>
                                <div className="max-h-64 overflow-y-auto border rounded-lg p-3 space-y-2">
                                    {nodes.map((node) => {
                                        const label = node.data?.label || `${node.type} ${node.id}`;
                                        const isSelected = selectedNodesForAlign.has(node.id);
                                        return (
                                            <div
                                                key={node.id}
                                                onClick={() => toggleNodeSelection(node.id)}
                                                className={`p-3 rounded-lg cursor-pointer transition-all border-2 ${
                                                    isSelected
                                                        ? darkMode 
                                                            ? 'bg-blue-900 border-blue-600' 
                                                            : 'bg-blue-50 border-blue-500'
                                                        : darkMode
                                                            ? 'bg-gray-700 border-gray-600 hover:bg-gray-600'
                                                            : 'bg-white border-gray-200 hover:bg-gray-50'
                                                }`}
                                            >
                                                <div className="flex items-center gap-3">
                                                    <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                                                        isSelected
                                                            ? 'bg-blue-600 border-blue-600'
                                                            : darkMode
                                                                ? 'border-gray-500'
                                                                : 'border-gray-300'
                                                    }`}>
                                                        {isSelected && <Check size={14} className="text-white" />}
                                                    </div>
                                                    <span className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                        {label}
                                                    </span>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                                <p className={`text-xs mt-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                    Selected: {selectedNodesForAlign.size} node(s)
                                </p>
                            </div>

                            {selectedNodesForAlign.size >= 2 && (
                                <div className="mb-4">
                                    <label className={`block text-sm font-medium mb-3 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                                        Alignment Direction:
                                    </label>
                                    <div className="flex gap-3">
                                        <button
                                            onClick={() => setAlignDirection('horizontal')}
                                            className={`flex-1 px-4 py-3 rounded-lg border-2 transition-all ${
                                                alignDirection === 'horizontal'
                                                    ? 'bg-blue-600 border-blue-600 text-white'
                                                    : darkMode
                                                        ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                        : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                            }`}
                                        >
                                            <div className="flex flex-col items-center gap-1">
                                                <AlignLeft size={20} />
                                                <span className="text-sm font-medium">Horizontal</span>
                                                <span className="text-xs opacity-75">Same Y position</span>
                                            </div>
                                        </button>
                                        <button
                                            onClick={() => setAlignDirection('vertical')}
                                            className={`flex-1 px-4 py-3 rounded-lg border-2 transition-all ${
                                                alignDirection === 'vertical'
                                                    ? 'bg-blue-600 border-blue-600 text-white'
                                                    : darkMode
                                                        ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                        : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                            }`}
                                        >
                                            <div className="flex flex-col items-center gap-1">
                                                <div className="rotate-90">
                                                    <AlignLeft size={20} />
                                                </div>
                                                <span className="text-sm font-medium">Vertical</span>
                                                <span className="text-xs opacity-75">Same X position</span>
                                            </div>
                                        </button>
                                    </div>
                                </div>
                            )}

                            <div className="flex justify-end gap-3">
                                <button
                                    onClick={() => {
                                        setShowAlignModal(false);
                                        setSelectedNodesForAlign(new Set());
                                        setAlignDirection(null);
                                    }}
                                    className={`px-4 py-2 text-sm font-medium ${darkMode ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={executeAlign}
                                    disabled={selectedNodesForAlign.size < 2 || !alignDirection}
                                    className={`px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-lg ${
                                        selectedNodesForAlign.size < 2 || !alignDirection
                                            ? 'opacity-50 cursor-not-allowed'
                                            : 'hover:bg-purple-700'
                                    }`}
                                >
                                    Align
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Line Style Selection Modal */}
            {showLineStyleModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className={`rounded-xl shadow-2xl max-w-md w-full mx-4 ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                        <div className={`px-6 py-4 border-b flex items-center justify-between ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-100'}`}>
                            <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Choose Line Style</h3>
                            <button onClick={handleCancelLineStyle} className={`${darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-600'}`}>
                                <X size={20} />
                            </button>
                        </div>
                        <div className="p-6">
                            <div className="mb-4">
                                <label className={`block text-sm font-medium mb-3 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                                    Select line style for this connection:
                                </label>
                                <div className="flex gap-3">
                                    <button
                                        onClick={() => handleLineStyleChoice(false)}
                                        className={`flex-1 px-4 py-3 rounded-lg border-2 transition-all ${
                                            darkMode
                                                ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                        }`}
                                    >
                                        <div className="flex flex-col items-center gap-2">
                                            <div className="w-full h-1 bg-gray-700 rounded"></div>
                                            <span className="text-sm font-medium">Solid Line</span>
                                        </div>
                                    </button>
                                    <button
                                        onClick={() => handleLineStyleChoice(true)}
                                        className={`flex-1 px-4 py-3 rounded-lg border-2 transition-all ${
                                            darkMode
                                                ? 'bg-gray-700 border-gray-600 text-gray-200 hover:bg-gray-600'
                                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                        }`}
                                    >
                                        <div className="flex flex-col items-center gap-2">
                                            <div className="w-full h-1 bg-gray-700 rounded" style={{ backgroundImage: 'repeating-linear-gradient(to right, #374151 0, #374151 4px, transparent 4px, transparent 8px)' }}></div>
                                            <span className="text-sm font-medium">Dashed Line</span>
                                        </div>
                                    </button>
                                </div>
                            </div>
                            <div className="flex justify-end">
                                <button
                                    onClick={handleCancelLineStyle}
                                    className={`px-4 py-2 text-sm font-medium ${darkMode ? 'text-gray-300 hover:text-gray-100' : 'text-gray-600 hover:text-gray-800'}`}
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Hardware List Modal */}
            {showHardwareListModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className={`rounded-xl shadow-2xl max-w-6xl w-full mx-4 max-h-[90vh] flex flex-col ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                        <div className={`px-6 py-4 border-b flex items-center justify-between ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-100'}`}>
                            <h3 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Hardware List</h3>
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={exportHardwareListToCSV}
                                    className={`px-3 py-1.5 text-sm font-medium rounded-lg flex items-center gap-1.5 ${
                                        darkMode 
                                            ? 'bg-blue-600 hover:bg-blue-700 text-white' 
                                            : 'bg-blue-600 hover:bg-blue-700 text-white'
                                    }`}
                                    title="Export to CSV"
                                >
                                    <FileSpreadsheet size={16} /> Export CSV
                                </button>
                                <button
                                    onClick={copyHardwareList}
                                    className={`px-3 py-1.5 text-sm font-medium rounded-lg flex items-center gap-1.5 ${
                                        darkMode 
                                            ? 'bg-gray-700 hover:bg-gray-600 text-white border border-gray-600' 
                                            : 'bg-gray-100 hover:bg-gray-200 text-gray-700 border border-gray-300'
                                    }`}
                                    title="Copy to clipboard"
                                >
                                    <Copy size={16} /> Copy
                                </button>
                                <button 
                                    onClick={() => setShowHardwareListModal(false)} 
                                    className={`${darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-400 hover:text-gray-600'}`}
                                >
                                    <X size={20} />
                                </button>
                            </div>
                        </div>
                        <div className="flex-1 overflow-y-auto p-6">
                            <div className="mb-4 flex items-center justify-between">
                                {showAddColumnInput ? (
                                    <div className="flex items-center gap-2">
                                        <input
                                            type="text"
                                            value={newColumnName}
                                            onChange={(e) => setNewColumnName(e.target.value)}
                                            onKeyDown={handleAddColumnKeyDown}
                                            placeholder="Enter column name"
                                            autoFocus
                                            className={`px-3 py-1.5 border rounded-lg text-sm focus:ring-2 focus:ring-green-500 focus:border-green-500 outline-none ${
                                                darkMode 
                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                    : 'border-gray-300 bg-white text-gray-900'
                                            }`}
                                        />
                                        <button
                                            onClick={addCustomColumn}
                                            className={`px-3 py-1.5 text-sm font-medium rounded-lg flex items-center gap-1.5 ${
                                                darkMode 
                                                    ? 'bg-green-600 hover:bg-green-700 text-white' 
                                                    : 'bg-green-600 hover:bg-green-700 text-white'
                                            }`}
                                            title="Add column"
                                        >
                                            <Plus size={16} /> Add
                                        </button>
                                        <button
                                            onClick={() => {
                                                setShowAddColumnInput(false);
                                                setNewColumnName('');
                                            }}
                                            className={`px-3 py-1.5 text-sm font-medium rounded-lg ${
                                                darkMode 
                                                    ? 'bg-gray-700 hover:bg-gray-600 text-white border border-gray-600' 
                                                    : 'bg-gray-100 hover:bg-gray-200 text-gray-700 border border-gray-300'
                                            }`}
                                            title="Cancel"
                                        >
                                            Cancel
                                        </button>
                                    </div>
                                ) : (
                                    <button
                                        onClick={() => setShowAddColumnInput(true)}
                                        className={`px-3 py-1.5 text-sm font-medium rounded-lg flex items-center gap-1.5 ${
                                            darkMode 
                                                ? 'bg-green-600 hover:bg-green-700 text-white' 
                                                : 'bg-green-600 hover:bg-green-700 text-white'
                                        }`}
                                        title="Add custom column"
                                    >
                                        <Plus size={16} /> Add Column
                                    </button>
                                )}
                            </div>
                            <div className="overflow-x-auto">
                                <table className={`w-full border-collapse ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                    <thead>
                                        <tr className={`border-b-2 ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Device</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Quantity</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Device Name</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Component Type</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Manufacturer</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>MAC Address</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>IP Address</th>
                                            <th className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Point of Contact</th>
                                            {customColumns.map(col => (
                                                <th key={col.id} className={`px-4 py-3 text-left text-sm font-semibold ${darkMode ? 'text-gray-300' : 'text-gray-700'} relative`}>
                                                    <div className="flex items-center gap-2">
                                                        <span>{col.name}</span>
                                                        <button
                                                            onClick={() => removeCustomColumn(col.id)}
                                                            className={`p-0.5 rounded hover:bg-red-500 hover:text-white ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}
                                                            title="Remove column"
                                                        >
                                                            <X size={12} />
                                                        </button>
                                                    </div>
                                                </th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {hardwareList.map((item, index) => {
                                            const Icon = item.icon;
                                            const colorClasses: Record<string, string> = {
                                                blue: 'text-blue-600',
                                                red: 'text-red-600',
                                                green: 'text-green-600',
                                                purple: 'text-purple-600',
                                                cyan: 'text-cyan-600',
                                                orange: 'text-orange-600',
                                                indigo: 'text-indigo-600',
                                                teal: 'text-teal-600',
                                                pink: 'text-pink-600',
                                                amber: 'text-amber-600',
                                                slate: 'text-slate-600',
                                                emerald: 'text-emerald-600',
                                                rose: 'text-rose-600',
                                                violet: 'text-violet-600',
                                            };
                                            const iconColorClass = colorClasses[item.color] || 'text-gray-600';
                                            return (
                                                <tr 
                                                    key={item.deviceType} 
                                                    className={`border-b ${darkMode ? 'border-gray-700 hover:bg-gray-700/50' : 'border-gray-200 hover:bg-gray-50'}`}
                                                >
                                                    <td className="px-4 py-3">
                                                        <div className="flex items-center gap-2">
                                                            <Icon size={18} className={iconColorClass} />
                                                            <span className="font-medium">{item.label}</span>
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className="font-semibold">{item.quantity}</span>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <input
                                                            type="text"
                                                            value={item.deviceName}
                                                            onChange={(e) => updateHardwareListField(item.deviceType, 'deviceName', e.target.value)}
                                                            placeholder="Device Name"
                                                            className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                darkMode 
                                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                                    : 'border-gray-300 bg-white'
                                                            }`}
                                                        />
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <input
                                                            type="text"
                                                            value={item.componentType}
                                                            onChange={(e) => updateHardwareListField(item.deviceType, 'componentType', e.target.value)}
                                                            placeholder="Component Type"
                                                            className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                darkMode 
                                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                                    : 'border-gray-300 bg-white'
                                                            }`}
                                                        />
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <input
                                                            type="text"
                                                            value={item.manufacturer}
                                                            onChange={(e) => updateHardwareListField(item.deviceType, 'manufacturer', e.target.value)}
                                                            placeholder="Manufacturer"
                                                            className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                darkMode 
                                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                                    : 'border-gray-300 bg-white'
                                                            }`}
                                                        />
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <input
                                                            type="text"
                                                            value={item.macAddress}
                                                            onChange={(e) => updateHardwareListField(item.deviceType, 'macAddress', e.target.value)}
                                                            placeholder="00:00:00:00:00:00"
                                                            className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                darkMode 
                                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                                    : 'border-gray-300 bg-white'
                                                            }`}
                                                        />
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <input
                                                            type="text"
                                                            value={item.ipAddress}
                                                            onChange={(e) => updateHardwareListField(item.deviceType, 'ipAddress', e.target.value)}
                                                            placeholder="192.168.1.1"
                                                            className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                darkMode 
                                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                                    : 'border-gray-300 bg-white'
                                                            }`}
                                                        />
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <input
                                                            type="text"
                                                            value={item.pointOfContact}
                                                            onChange={(e) => updateHardwareListField(item.deviceType, 'pointOfContact', e.target.value)}
                                                            placeholder="Name, Email, Phone"
                                                            className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                darkMode 
                                                                    ? 'bg-gray-700 border-gray-600 text-white' 
                                                                    : 'border-gray-300 bg-white'
                                                            }`}
                                                        />
                                                    </td>
                                                    {customColumns.map(col => (
                                                        <td key={col.id} className="px-4 py-3">
                                                            <input
                                                                type="text"
                                                                value={item.customFields[col.id] || ''}
                                                                onChange={(e) => updateHardwareListCustomField(item.deviceType, col.id, e.target.value)}
                                                                placeholder={col.name}
                                                                className={`w-full px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none ${
                                                                    darkMode 
                                                                        ? 'bg-gray-700 border-gray-600 text-white' 
                                                                        : 'border-gray-300 bg-white'
                                                                }`}
                                                            />
                                                        </td>
                                                    ))}
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                                {hardwareList.length === 0 && (
                                    <div className={`text-center py-8 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                        No hardware devices found in the diagram.
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
