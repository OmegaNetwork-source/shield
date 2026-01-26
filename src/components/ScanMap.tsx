import React, { useCallback, useMemo } from 'react';
import ReactFlow, {
    Node,
    Edge,
    Background,
    Controls,
    MiniMap,
    useNodesState,
    useEdgesState,
    MarkerType,
    NodeTypes,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { CrawlResult } from '../scanner/types';
import { FileText, Link as LinkIcon, AlertTriangle, Shield, Globe, Activity } from 'lucide-react';

interface ScanMapProps {
    crawlResults?: CrawlResult[];
    vulnerabilities?: any[];
    onNodeClick?: (nodeId: string) => void;
}

// Custom Node Components
const PageNode = ({ data }: any) => (
    <div className={`p-0 rounded-xl overflow-hidden glass-card min-w-[200px] border-2 transition-all duration-300 ${data.hasVulns
        ? 'border-red-500/50 shadow-lg shadow-red-900/20'
        : data.isExternal
            ? 'border-slate-700/50 opacity-80'
            : 'border-cyan-500/30'
        }`}>
        <div className={`px-4 py-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wider ${data.hasVulns
            ? 'bg-red-500/20 text-red-400'
            : data.isExternal
                ? 'bg-slate-800 text-slate-400'
                : 'bg-cyan-500/10 text-cyan-400'
            }`}>
            {data.isExternal ? (
                <Globe className="w-3.5 h-3.5" />
            ) : data.hasVulns ? (
                <AlertTriangle className="w-3.5 h-3.5 animate-pulse" />
            ) : (
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
            )}
            <span className="truncate">{data.label}</span>
        </div>

        <div className="p-3">
            <div className="text-[10px] font-mono text-slate-500 truncate mb-2">
                {data.url}
            </div>

            {data.vulnCount > 0 && (
                <div className="flex items-center gap-2">
                    <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                        <div
                            className="h-full bg-red-500"
                            style={{ width: `${Math.min(100, data.vulnCount * 20)}%` }}
                        />
                    </div>
                    <span className="text-[10px] font-bold text-red-400">
                        {data.vulnCount} RISK
                    </span>
                </div>
            )}

            {!data.hasVulns && !data.isExternal && (
                <div className="text-[10px] text-cyan-500/60 font-medium flex items-center gap-1">
                    <div className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
                    SECURE NODE
                </div>
            )}
        </div>
    </div>
);

const nodeTypes: NodeTypes = {
    page: PageNode,
};

export default function ScanMap({ crawlResults = [], vulnerabilities = [], onNodeClick }: ScanMapProps) {
    // Transform crawl results into graph
    const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
        if (!crawlResults || crawlResults.length === 0) return { nodes: [], edges: [] };

        const nodes: Node[] = [];
        const edges: Edge[] = [];
        const processedUrls = new Set<string>();

        const getDomain = (u: string) => {
            try { return new URL(u).hostname; } catch { return ''; }
        };

        const baseUrl = crawlResults.length > 0 ? crawlResults[0].url : '';
        const baseDomain = getDomain(baseUrl);

        // 1. Create Nodes
        crawlResults.forEach((page, index) => {
            const domain = getDomain(page.url);
            const isExternal = domain !== baseDomain;
            const pageVulns = vulnerabilities.filter(v => v.location === page.url || v.url === page.url);

            // Tiered radial layout for a more "organized" look
            const tier = index === 0 ? 0 : 1 + Math.floor(Math.log2(index + 1));
            const angle = (index * 137.5) * (Math.PI / 180); // Fibonacci spiral
            const radius = tier * 180;
            const x = Math.cos(angle) * radius;
            const y = Math.sin(angle) * radius;

            nodes.push({
                id: page.url,
                type: 'page',
                position: { x, y },
                data: {
                    label: new URL(page.url).pathname || '/',
                    url: page.url,
                    isExternal,
                    hasVulns: pageVulns.length > 0,
                    vulnCount: pageVulns.length
                },
            });
            processedUrls.add(page.url);
        });

        // 2. Create Edges
        crawlResults.forEach((page) => {
            page.links.forEach((link) => {
                if (processedUrls.has(link)) {
                    edges.push({
                        id: `${page.url}-${link}`,
                        source: page.url,
                        target: link,
                        type: 'smoothstep',
                        markerEnd: {
                            type: MarkerType.ArrowClosed,
                            color: '#06b6d4',
                        },
                        style: {
                            stroke: '#334155',
                            strokeWidth: processedUrls.has(link) ? 2 : 1,
                            opacity: 0.6
                        },
                        animated: vulnerabilities.some(v => v.url === link),
                    });
                }
            });
        });

        return { nodes, edges };
    }, [crawlResults, vulnerabilities]);

    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

    React.useEffect(() => {
        setNodes(initialNodes);
        setEdges(initialEdges);
    }, [initialNodes, initialEdges, setNodes, setEdges]);

    return (
        <div className="w-full h-[600px] bg-[#0f172a] rounded-xl overflow-hidden relative shadow-2xl border border-slate-800">
            {/* Grid Overlay */}
            <div className="absolute inset-0 pointer-events-none opacity-20"
                style={{ backgroundImage: 'radial-gradient(#334155 1px, transparent 1px)', backgroundSize: '24px 24px' }} />

            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={nodeTypes}
                onNodeClick={(_, node) => onNodeClick && onNodeClick(node.id)}
                fitView
                attributionPosition="bottom-right"
            >
                <Background color="#1e293b" gap={20} size={1} />
                <Controls className="bg-slate-800 border-slate-700 text-white fill-white" />
                <MiniMap
                    style={{ background: '#1e293b' }}
                    nodeColor={(n) => n.data?.hasVulns ? '#ef4444' : '#06b6d4'}
                    maskColor="rgba(15, 23, 42, 0.7)"
                    className="border border-slate-700 rounded-lg"
                />
            </ReactFlow>

            {/* HUD Overlay */}
            <div className="absolute top-4 left-4 pointer-events-none">
                <div className="bg-slate-900/80 backdrop-blur-md border border-slate-700 px-3 py-2 rounded-lg text-[10px] font-mono text-cyan-400 uppercase tracking-tighter">
                    <div className="flex items-center gap-2 mb-1">
                        <Activity className="size-3 animate-pulse" />
                        Live Attack Surface Map
                    </div>
                    <div className="text-slate-500">Nodes: {nodes.length} | Vulnerabilities: {vulnerabilities.length}</div>
                </div>
            </div>
        </div>
    );
}
