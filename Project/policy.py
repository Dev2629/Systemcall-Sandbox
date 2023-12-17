import angr
import networkx as nx
from utils import *
import sys
import requests
from bs4 import BeautifulSoup
from collections import deque

################ Some Intilization of Anger ##########################################
proj = angr.Project(sys.argv[1], auto_load_libs=False)
cfg = proj.analyses.CFGFast()
G = nx.DiGraph()
call_graph = cfg.kb.callgraph
main = cfg.kb.functions.get("main")
root_block = cfg.get_node(main.addr)
pd = list(nx.dfs_preorder_nodes(call_graph, source=main.addr))
graph = call_graph
snode = cfg.kb.functions['main']
tg = snode.transition_graph

G = nx.DiGraph()
G.add_node("mainstart")
opy = nx.DiGraph()

######################################################################################



######## Gnerating Graph ###############

def GeneratePng(graph):
    agraph = nx.nx_agraph.to_agraph(graph)
    agraph.layout(prog='dot')  # Choose a layout engine (e.g., 'dot', 'neato', 'fdp', etc.)
    agraph.draw('graph.png')   # Optionally, save the graph as an image file
    agraph.draw(format='png', prog='dot') 

  

# def custom_dfs(graph, start_node, prev,visited=None):
#     if visited is None:
#         visited = set()

#     visited.add(start_node)
#     if start_node!='mainstart':
#             if graph.in_degree(start_node)>1:
#                 G.add_node(start_node)
#                 pre = prev.pop()
#                 G.add_edge(pre,start_node)
#                 prev.append(start_node)  

#             if graph.out_degree(start_node)>1:
#                 for successor in graph.successors(start_node):
#                     if successor not in G.nodes():
#                         G.add_node(start_node)
#                         pre = prev.pop()
#                         G.add_edge(pre,start_node)
#                         for i in range(0,graph.out_degree(start_node)):
#                             prev.append(start_node)

#     for neighbor in graph.neighbors(start_node):
#         if neighbor not in visited:
#             edge_data = graph.get_edge_data(start_node, neighbor)
#             if edge_data is not None:
#                 label = edge_data.get('label')
#                 if label is not None:
#                     G.add_node(neighbor)
#                     pre = prev.pop()
#                     G.add_edge(pre,neighbor,label = label)
#                     prev.append(neighbor)
#             custom_dfs(graph, neighbor, prev,visited)
#         else:
#             if neighbor in G.nodes():
#                 G.add_node(start_node)
#                 pre  = prev.pop()
#                 prev.append(start_node)
#                 G.add_edge(pre,start_node)
#                 G.add_edge(start_node,neighbor)



# def Efficient(graph):

#     prev = ['mainstart']
#     custom_dfs(graph,list(graph.nodes())[0],prev)
#     self_loops = []
#     for source, target in G.edges():
#         if source == target:
#             self_loops.append((source, target))
#     G.remove_edges_from(self_loops)


########### For Minimizing the Graph ########################
def Final(graph,sys):
    saviour = []
    opy.add_node("End")


    for source, target, data in graph.edges(data=True):
        edge_data = graph.get_edge_data(source, target)
        if ('label' in edge_data):
            label = edge_data['label']
            print(label)
            if label in sys or source == "Start main" or target == 'mainend':
                saviour.append([source,target,label])        
    for i in saviour:
        opy.add_node(i[0])
        opy.add_node(i[1])
        opy.add_edge(i[0],i[1],label = i[2])

    opy.add_node("Start main")
    for i in graph.successors("Start main"):
        opy.add_node(i)
        opy.add_edge('Start main',i,label = 'op')
        saviour.append(['Start main',i,'op'])
    
    for i in saviour:
        for j in saviour:
                all_paths = list(nx.all_simple_paths(graph, i[1], j[0]))
                if len(all_paths):
                    for path in all_paths:
                        flag = 0
                        for k in range(1,len(path)):
                            edge_data = graph.get_edge_data(path[k-1], path[k])
                            if ('label' in edge_data):
                                label = edge_data['label']
                                if label is not None:
                                    flag = 1
                                    break
                        if flag!=1:
                            opy.add_edge(i[1],j[0])   

    for i in opy.nodes():
        if(i!="Start" and i!= "End"):
            if(opy.out_degree(i) == 0):
                opy.add_edge(i,"End")


#####################################################



########## For Generating System Call List ###########################################
def syslist(graph):

    url = "https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html"

    response = requests.get(url)

    soup = BeautifulSoup(response.content, 'html.parser')

    table = soup.find('table')

    sys = []

    for row in table.find_all('tr'):
        columns = row.find_all('td')
        if len(columns) >= 2:
            name = columns[0].text.strip()  
            sys.append(name)
    return sys        

#################################################
            
def generatePydot(G, name= "graph.dot"):
    A = nx.nx_agraph.to_agraph(G)
    A.write(name)

##################################################

def merged_graph(node ,sys):
    if node is None:
        return
    tg = node.transition_graph
    Name = node.name
    nodes = list(tg.nodes())
    if nodes is None:
        return
    tg.add_node('Start '+Name, label=Name+"start", color='pink', style='filled')
    tg.add_edge('Start '+Name, nodes[0],)
    tg.add_node(Name+"end", label=Name+'end', color='pink', style='filled')   
    userFun = []
    Remove_fun = []
    edges_to_remove = []  # Create a list to collect edges to be removed
    edges_to_add = []
    for u, v, attr in list(tg.edges(data=True)):  # Convert to a list to iterate safely
        if isinstance(v, angr.knowledge_plugins.functions.function.Function) and v.name != 'UnresolvableCallTarget':
            if len(list(tg.successors(u))) == 2:
                nextnode = list(tg.successors(u))[1]
                Remove_fun.append(v)
                edges_to_remove.append((u, v))  # Collect edges to be removed
                edges_to_remove.append((u, nextnode))  # Collect edges to be removed
                edges_to_add.append((u,nextnode, v.name))
                 # Modify the temporary graph
                if v.name not in sys:
                    userFun.append(v)
            else :
                if v not in Remove_fun:
                    Remove_fun.append(v)
                tg.add_edge(u,Name+'end',label = 'exit')

    # Remove collected edges from the original graph
    for u, v in edges_to_remove:
        tg.remove_edge(u, v)

    for u, v, label in edges_to_add:
        tg.add_edge(u, v, label=label)

    # Remove nodes from the original graph
    tg.remove_nodes_from(Remove_fun)

    leaf_nodes = [node for node in tg.nodes() if tg.degree(node) == 1]
    for i in leaf_nodes:
        if(isinstance(i, angr.codenode.BlockNode)):        
            tg.add_edge(i,Name+'end') 

    if(len(userFun)):
        for i in userFun:
             #print(i.name)
             if ("sub_" in i.name or "sys_" in i.name):
                continue
             include = []
             g = merged_graph(i,sys)
             #GeneratePng(g)
             if g is None:
                continue
             rm = []
             remove = []
             for u, v, attr in tg.edges(data=True):
                edge_data = tg.get_edge_data(u, v)
                if 'label' in edge_data:
                    nm = edge_data['label']
                   # print(nm)
                  #  print("II wala ",i.name)
                    if i.name == nm:
                        first = -1
                        last = -1
                        nody = list(g.nodes())
                        first = "Start "+ i.name
                        last = i.name + "end"
                        for e in g.nodes():
                            if isinstance(e,str):
                                if (str(e) == first):
                                    first = e
                                if (str(e) == last):
                                    last = e
                        #print(first)
                        #print(g.nodes())
                        rm.append(first)
                        rm.append(last)
                        remove.append((u,v))
                        succ = list(g.successors(first))
                        predd = list(g.predecessors(last))
                        for k in succ:
                            tg.add_edge(u,k)
                        for k in predd:
                            tg.add_edge(k,v)
                        g.remove_node(first)
                        g.remove_node(last)
                        tg.add_nodes_from(list(g.nodes()))
                        break     
             tg.add_edges_from(list(g.edges(data=True)))
             tg.remove_edges_from(remove)
    return tg



#######################################################

sys = syslist(cfg.graph)
sys = [item for item in sys if item != ""]
G = merged_graph(snode,sys)
#GeneratePng(G)
Final(G,sys)
GeneratePng(opy)


################## For Creating Proper Matrix(DFA) of System call graph Write the Matrix in Matrix.txt ############################

for source, target, data in opy.edges(data=True):
    current_label = data.get("label")  # Get the current label
    if current_label is None:
        new_label = 'eps'  # Modify the label
        data["label"] = new_label  # Update the label

#GeneratePng(G)
graph = opy
node_to_index = {}
node_to_index["Start main"] = 0
index = 1
for node in graph.nodes():
    if node != 'Start main':
        node_to_index[node] = index
        index += 1
#print(node_to_index)

ind = int(index)
# Define the URL of the webpage
url = "https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html"

# Send an HTTP GET request to the webpage
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Parse the HTML content of the webpage
    soup = BeautifulSoup(response.text, "html.parser")

    # Find the table containing the data (assuming it's the first table on the page)
    table = soup.find("table")

    # Initialize an empty dictionary to store the data
    syscall_dict = {}

    # Iterate through the rows of the table
    for row in table.find_all("tr"):
        # Extract the columns
        columns = row.find_all("td")
        if len(columns) >= 3:
            # Extract the index (first column) and its value (third column)
            index = columns[0].get_text()
            value = columns[4].get_text()

            # Store the data in the dictionary
            syscall_dict[index] = value


graph_list = [[-2 for _ in range(ind)] for _ in range(ind)]
for source_node , target_node, edge in graph.edges(data=True):
    label = edge.get('label')
    source_index = node_to_index[source_node]
    target_index = node_to_index[target_node]
    #print(label)
    if label not in syscall_dict:
        graph_list[source_index][target_index] = -1
    else :
        graph_list[source_index][target_index] = syscall_dict[label]
print("Write This Length Of Matrix in You Bpf Code Manually : ",len(graph_list))

with open('../libbpf-bootstrap/Code/Phase_2/matrix.txt', 'w') as file:
    for row in graph_list:
        row_str = ' '.join(map(str, row))  # Convert row values to strings and join with spaces
        file.write(row_str + '\n')