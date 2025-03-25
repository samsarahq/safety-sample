import React, { useState, useEffect } from 'react';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { Trash2 } from 'lucide-react';

const OrganizationTable = () => {
  const [organizations, setOrganizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchOrganizations = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/organizations');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      setOrganizations(data);
    } catch (error) {
      console.error('Error fetching organizations:', error);
      setError('Failed to load organizations. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const deleteOrganization = async (orgId) => {
    try {
      const response = await fetch(`/api/organizations/${orgId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      // Refresh the organization list after successful deletion
      fetchOrganizations();
    } catch (error) {
      console.error('Error deleting organization:', error);
      setError('Failed to delete organization. Please try again later.');
    }
  };

  useEffect(() => {
    fetchOrganizations();
  }, []);

  if (loading) {
    return (
      <div className="w-full mt-8 text-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mx-auto"></div>
        <p className="mt-2 text-gray-600">Loading organizations...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full mt-8 p-4 bg-red-50 border border-red-200 rounded-lg">
        <p className="text-red-600">{error}</p>
        <button 
          onClick={fetchOrganizations}
          className="mt-2 text-red-600 hover:text-red-800 underline"
        >
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="w-full mt-8">
      <h2 className="text-xl font-semibold mb-4">Connected Organizations</h2>
      <div className="border rounded-lg overflow-hidden">
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 sticky top-0 bg-gray-50">Org ID</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 sticky top-0 bg-gray-50">Org Name</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 sticky top-0 bg-gray-50">Last Updated</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500 sticky top-0 bg-gray-50">Expires At</th>
                <th className="px-4 py-3 text-right text-sm font-medium text-gray-500 sticky top-0 bg-gray-50">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {organizations.length > 0 ? (
                organizations.map((org) => (
                  <tr key={org.org_id} className="bg-white hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-900">{org.org_id}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">{org.org_name}</td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {new Date(org.last_updated).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {new Date(org.expires_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <AlertDialog>
                        <AlertDialogTrigger>
                          <button className="text-red-600 hover:text-red-800">
                            <Trash2 className="h-5 w-5" />
                          </button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Delete Organization</AlertDialogTitle>
                            <AlertDialogDescription>
                              Are you sure you want to delete {org.org_name}? This will remove their access token.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => deleteOrganization(org.org_id)}>
                              Delete
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="px-4 py-8 text-center text-gray-500">
                    No organizations connected
                  </td>
                </tr>
              )}
              {/* Add empty rows to maintain minimum height */}
              {organizations.length < 5 && Array.from({ length: 5 - organizations.length }).map((_, index) => (
                <tr key={`empty-${index}`} className="bg-white">
                  <td colSpan="5" className="px-4 py-3">&nbsp;</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default OrganizationTable;